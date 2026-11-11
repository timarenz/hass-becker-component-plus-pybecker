"""Helper for Becker centronic USB Stick."""
import asyncio
import logging
from pathlib import Path
import re
import time
import threading
import queue
from typing import Any, Callable, Optional, Tuple
import os
import sys
import serial
import serial.tools.list_ports

try:
    from fcntl import ioctl
except ImportError:  # pragma: no cover - non-POSIX platforms
    ioctl = None

# Linux _IO('U', 20) ioctl constant for resetting a USB device via usbfs
USBDEVFS_RESET = (ord("U") << 8) | 20
BECKER_USB_VID = "2638"
BECKER_USB_PID = "0013"
SYSFS_TTY_PATH = Path("/sys/class/tty")
SYSFS_USB_PATH = Path("/sys/bus/usb/devices")
DEV_BUS_USB_PATH = Path("/dev/bus/usb")
MAX_READ_BUFFER = 4096

STX = b'\x02'
ETX = b'\x03'

CODE_PREFIX = "0000000002010B"  # 0-23 (24 chars)
CODE_SUFFIX = "000000"
CODE_21 = "021"
CODE_REMOTE = "01"  # centronic remote control used "02" while contralControl seem to use "01"

DEFAULT_DEVICE_NAME = '/dev/serial/by-id/usb-BECKER-ANTRIEBE_GmbH_CDC_RS232_v125_Centronic-if00'

MESSAGE = re.compile(
      STX
    + CODE_PREFIX.encode()
    + rb'[0-9A-F]{4,4}'
    + CODE_SUFFIX.encode()
    + rb'(?P<unit_id>[0-9A-F]{5,5})'
    + rb'[0-9A-F]{6,6}'
    + rb'(?P<channel>[0-9A-F]{1,1})'
    + rb'00'
    + rb'(?P<command>[0-9A-F]{1,1})'
    + rb'(?P<argument>[0-9A-F]{1,1})'
    + rb'[0-9A-F]{2,2}'
    + ETX, re.I
)

COMMANDS = {b'0': 'RELEASE', b'1': 'HALT', b'2': 'UP', b'4': 'DOWN', b'8': 'TRAIN'}
COMMUNICATION_TIMEOUT = 0.3

_LOGGER = logging.getLogger(__name__)


def hex2(n):
    """Return word"""
    return '%02X' % (n & 0xFF)


def hex4(n):
    """Return dword"""
    return '%04X' % (n & 0xFFFF)


def checksum(code):
    """Calculate checksum"""
    code_length = len(code)
    if code_length != 40:
        _LOGGER.error("The code must be 40 characters long (without <STX>, <ETX> and checksum)")
        return
    code_sum = 0
    i = 0
    while i < code_length:
        hex_code = code[i] + code[i + 1]
        code_sum += int(hex_code, 16)
        i += 2
    return '%s%s' % (code.upper(), hex2(0x03 - code_sum))


def generate_code(channel, unit, cmd_code, with_checksum=True, remote_type=None):
    """Generate code"""
    unit_id = unit[0]  # contains the unit code in hex (5 chars)
    unit_inc = unit[1]  # contains the next increment (required to convert into hex4)
    if remote_type is None:
        remote_type = CODE_REMOTE

    if channel == 0:
        # channel 0 may be used for wall mounted sender (primary used as master sender)
        code = CODE_PREFIX + hex4(unit_inc) + CODE_SUFFIX + unit_id + CODE_21 + "00" + hex2(channel) + '00' + hex2(
            cmd_code)
    else:
        code = CODE_PREFIX + hex4(unit_inc) + CODE_SUFFIX + unit_id + CODE_21 + remote_type + hex2(channel) + '00' \
               + hex2(cmd_code)
    return checksum(code) if with_checksum else code

def finalize_code(code):
    """Add frame"""
    return b"".join([STX, code.encode(), ETX])


class BeckerConnectionError(Exception):
    """Error class for Becker centronic USB Stick."""
    pass


class BeckerConnection():
    """
    Connection class for Becker centronic USB Stick.
    """
    # Minimum seconds between full teardown/rebuild attempts of the
    # underlying pyserial object once it gets stuck failing to open.
    RECONNECT_REBUILD_INTERVAL = 10
    WRITE_TIMEOUT = 2.0
    USB_RESET_COOLDOWN = 30.0
    USB_POST_RESET_SETTLE = 1.0
    USB_REAPPEAR_TIMEOUT = 5.0

    def __init__(self, device: str) -> None:
        """Initialize connection."""
        self._device, self._is_serial = self._validate_device(device)
        self._connection = self._build_serial()
        self._last_rebuild_attempt = 0.0
        self._last_usb_reset = 0.0
        self._open_error_logged = False
        self._open()

    def _build_serial(self):
        """Create a fresh pyserial Serial object for the configured device."""
        extra_kwargs = {"exclusive": True} if (self._is_serial and os.name == "posix") else {}
        try:
            return serial.serial_for_url(
                self.device,
                baudrate=115200,
                timeout=0,
                write_timeout=self.WRITE_TIMEOUT,
                do_not_open=True,
                **extra_kwargs,
            )
        except serial.SerialException as err:
            raise BeckerConnectionError(
                "Error when trying to establish connection using {}.".format(self.device)
            ) from err

    @property
    def is_serial(self) -> bool:
        """Return if device is serial port."""
        return self._is_serial

    @property
    def is_open(self) -> bool:
        """Return whether the underlying connection is currently open."""
        return bool(self._connection and self._connection.is_open)

    @property
    def device(self) -> str:
        """Return device name."""
        return self._device

    def write(self, packet: bytes) -> None:
        """Write data, resetting the USB device and retrying once on failure."""
        self._open()
        if not self._connection.is_open:
            if not self.reset_usb():
                raise BeckerConnectionError(f"Serial connection to {self.device} is not open")
        try:
            self._connection.write(packet)
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.warning(
                "Write to %s failed (%s); resetting USB device and retrying once.",
                self.device,
                err,
            )
            if not self.reset_usb():
                raise BeckerConnectionError(
                    f"Write to {self.device} failed and USB recovery could not reopen port"
                ) from err
            self._connection.write(packet)

    def read(self) -> bytes:
        """Read data."""
        self._open()
        if not self._connection.is_open:
            return b""
        try:
            return self._connection.read(1024)
        except Exception as err:  # pylint: disable=broad-except
            # Re-connect on error (covers SerialException and raw OSError on unplug)
            _LOGGER.warning(
                "Read from %s failed (%s); closing serial connection for reconnect.",
                self.device,
                err,
            )
            self._open_error_logged = True
            self._close_quietly()
            try:
                self._connection = self._build_serial()
            except BeckerConnectionError:
                pass
            return b""

    def _close_quietly(self) -> None:
        """Close the underlying serial handle ignoring errors on dead fds."""
        try:
            self._connection.close()
        except Exception:  # pylint: disable=broad-except
            pass

    def _open(self) -> None:
        if self._connection.is_open:
            return
        if self.is_serial and "/dev/" in self.device and not os.path.exists(self.device):
            if not self._open_error_logged:
                _LOGGER.warning(
                    "Becker USB device %s is not present; waiting for reconnect.",
                    self.device,
                )
                self._open_error_logged = True
            return

        _LOGGER.debug("Try to open connection.")
        try:
            self._connection.open()
        except serial.SerialException as err:
            if self.is_serial:
                if not self._open_error_logged:
                    _LOGGER.warning(
                        "Establish connection to %s failed, will retry: %s", self.device, err
                    )
                    self._open_error_logged = True
                self._maybe_rebuild()
            else:
                _LOGGER.error("Establish connection to %s failed!", self.device)
        except Exception as err:     # pylint: disable=broad-except
            if not self._open_error_logged:
                _LOGGER.warning(
                    "Establish connection to %s failed, will retry: %s", self.device, err
                )
                self._open_error_logged = True
            self._maybe_rebuild()
        else:
            if self._open_error_logged:
                _LOGGER.info("Reconnected to Becker USB device %s.", self.device)
                self._open_error_logged = False

    def _find_usb_devfs_path(self) -> Optional[Path]:
        """Locate /dev/bus/usb/<bus>/<dev> for the configured Becker USB stick."""
        if not self.is_serial:
            return None

        candidates = []
        if "/dev/" in self.device and os.path.exists(self.device):
            tty_name = Path(os.path.realpath(self.device)).name
            tty_dev_link = SYSFS_TTY_PATH / tty_name / "device"
            try:
                cur = tty_dev_link.resolve()
                for _ in range(4):
                    candidates.append(cur)
                    cur = cur.parent
            except OSError:
                pass

        if SYSFS_USB_PATH.is_dir():
            try:
                for entry in SYSFS_USB_PATH.iterdir():
                    try:
                        vid = (entry / "idVendor").read_text(encoding="utf-8").strip().lower()
                        pid = (entry / "idProduct").read_text(encoding="utf-8").strip().lower()
                    except OSError:
                        continue
                    if vid == BECKER_USB_VID and pid == BECKER_USB_PID:
                        candidates.append(entry)
            except OSError:
                pass

        for usb_dir in candidates:
            try:
                busnum = int((usb_dir / "busnum").read_text(encoding="utf-8").strip())
                devnum = int((usb_dir / "devnum").read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                continue
            devfs = DEV_BUS_USB_PATH / f"{busnum:03d}" / f"{devnum:03d}"
            if devfs.exists():
                return devfs
        return None

    def reset_usb(self, force: bool = False) -> bool:
        """Close the serial port, issue a kernel USB port reset if permitted, and reopen."""
        usb_devfs = self._find_usb_devfs_path()
        # Close fd before USBDEVFS_RESET so cdc_acm releases ttyACM0 cleanly
        self._close_quietly()

        now = time.time()
        can_bus_reset = (
            self.is_serial
            and ioctl is not None
            and usb_devfs is not None
            and (force or (now - self._last_usb_reset >= self.USB_RESET_COOLDOWN))
        )
        if can_bus_reset:
            self._last_usb_reset = now
            try:
                fd = os.open(str(usb_devfs), os.O_WRONLY)
                try:
                    ioctl(fd, USBDEVFS_RESET, 0)
                finally:
                    os.close(fd)
                _LOGGER.warning(
                    "Issued kernel USB port reset (USBDEVFS_RESET) on %s for %s.",
                    usb_devfs,
                    self.device,
                )
                time.sleep(self.USB_POST_RESET_SETTLE)
                deadline = time.time() + self.USB_REAPPEAR_TIMEOUT
                while "/dev/" in self.device and not os.path.exists(self.device):
                    if time.time() >= deadline:
                        break
                    time.sleep(0.25)
            except OSError as err:
                _LOGGER.warning("Kernel USB port reset on %s failed: %s", usb_devfs, err)

        try:
            self._connection = self._build_serial()
        except BeckerConnectionError as err:
            _LOGGER.warning("Rebuild of serial connection to %s failed: %s", self.device, err)
            return False

        self._open()
        return self._connection.is_open

    def _maybe_rebuild(self) -> None:
        """Periodically tear down and recreate the underlying pyserial object."""
        now = time.time()
        if now - self._last_rebuild_attempt < self.RECONNECT_REBUILD_INTERVAL:
            return
        self._last_rebuild_attempt = now
        self._close_quietly()
        try:
            new_connection = self._build_serial()
        except BeckerConnectionError as err:
            _LOGGER.debug("Rebuild of serial connection to %s failed: %s", self.device, err)
            return
        self._connection = new_connection
        _LOGGER.info("Rebuilt serial connection object for %s after repeated failures.", self.device)

    def close(self) -> None:
        """Close connection"""
        self._close_quietly()

    @staticmethod
    def _validate_device(device: str) -> Tuple[str, bool]:
        """Validate device name."""
        is_serial = False
        is_socket = True
        if device is None:
            device = DEFAULT_DEVICE_NAME
        if "/dev/" in device:
            if not os.path.exists(device):
                # Do not abort setup if the USB stick is momentarily unplugged or re-enumerating
                _LOGGER.warning("Device %s does not exist yet; will connect once available.", device)
            is_serial = True
            is_socket = False
        elif sys.platform.startswith('win') and 'COM' in device.upper():
            if not device.upper() in [i.device for i in serial.tools.list_ports.comports()]:
                raise BeckerConnectionError("{} is not existing".format(device))
            is_serial = True
            is_socket = False
        elif "/" in device:
            is_socket = False
        if is_socket:
            if ':' in device:
                host, port = device.split(':', 1)
            else:
                host = device
                port = '5000'
            device = f'socket://{host}:{port}'
        return device, is_serial


class BeckerCommunicator(threading.Thread):
    """
    Communicator class for Becker centronic USB Stick.
    Handles sending and receiving RF commands with configurable queue and retry logic.
    """
    def __init__(
        self,
        device: str,
        callback: Callable[[re.Match], Any] = None,
        deamon: bool = True,
        queue_size: int = 100,
        retry_max: int = 3,
        retry_delay: float = 1.0
    ) -> None:
        '''Initialize communicator with configurable queue and retry parameters.'''
        super().__init__(daemon=deamon)

        # Store configuration
        self._queue_size = queue_size
        self._retry_max = retry_max
        self._retry_delay = retry_delay

        # Setup threading stop event, lock, and queue
        self._stop_flag = threading.Event()
        self._io_lock = threading.Lock()
        self._write_queue = queue.Queue(maxsize=queue_size)

        # Setup callback
        self._callback = callback

        # Setup interface
        self._connection = BeckerConnection(device=device)
        self._read_buffer = bytes()

        # timeout will be used within thread only
        self._timeout = time.time()

        _LOGGER.info(
            "BeckerCommunicator initialized: queue_size=%d, retry_max=%d, retry_delay=%.1fs",
            queue_size, retry_max, retry_delay
        )

    def run(self) -> None:
        '''Run BeckerCommunicator thread.'''
        _LOGGER.debug('BeckerCommunicator thread started.')
        callback_valid = self._callback is not None
        while True:
            # Read bytes from serial port
            if callback_valid:
                try:
                    with self._io_lock:
                        data = self._connection.read()
                except Exception as err:   # pylint: disable=broad-except
                    _LOGGER.warning(
                        "BeckerCommunicator read failed (%s). Will keep retrying without killing the thread.", err
                    )
                    data = bytes()
                if len(data) > 0:
                    self._timeout = time.time() + COMMUNICATION_TIMEOUT
                self._read_buffer += data
                try:
                    self._parse()
                except Exception:  # pylint: disable=broad-except
                    _LOGGER.exception("Error parsing received Becker RF packet")
                    self._read_buffer = bytes()
            # Get packet from write queue if timeout expired
            if self._timeout < time.time():
                try:
                    packet = self._write_queue.get(block=False)
                except queue.Empty:
                    pass
                else:
                    try:
                        with self._io_lock:
                            self._connection.write(packet)
                    except Exception as err:   # pylint: disable=broad-except
                        _LOGGER.warning(
                            "BeckerCommunicator failed to send packet (%s). Connection will be retried.", err
                        )
                    else:
                        self._timeout = time.time() + COMMUNICATION_TIMEOUT
                        self._log(packet, "Sent packet: ")

            # Sleep for thread switch and wait time between packets
            time.sleep(0.1)
            # Exit once stopped and either queue is drained or port is unavailable
            if self._stop_flag.is_set() and (
                self._write_queue.empty() or not self._connection.is_open
            ):
                break
        _LOGGER.debug('BeckerCommunicator thread stopped.')

    def stop(self) -> None:
        '''Stop BeckerCommunicator thread.'''
        self._stop_flag.set()

    def reset_usb(self, force: bool = True) -> bool:
        """Thread-safely reset the underlying USB device and reopen its serial port."""
        with self._io_lock:
            return self._connection.reset_usb(force=force)

    def _parse(self) -> None:
        """Parse received packets and run callback."""
        end = 0
        for data in MESSAGE.finditer(self._read_buffer):
            self._log(data.group(0), "Received packet: ")
            self._callback(data)
            end = data.end()
        if end > 0:
            self._read_buffer = self._read_buffer[end:]
        elif len(self._read_buffer) > MAX_READ_BUFFER:
            # Retain tail in case an in-flight 44-byte frame straddles the boundary
            self._read_buffer = self._read_buffer[-64:]

    def _log(self, packet: bytes, text: str = "") -> None:
        """Log packets."""
        if _LOGGER.getEffectiveLevel() <= logging.DEBUG:
            match = MESSAGE.search(packet)
            if match is not None:
                if match.group('command') in COMMANDS:
                    command = COMMANDS[match.group('command')]
                else:
                    command = match.group('command').decode()
                _LOGGER.debug(
                    "%sunit_id: %s, channel: %s, command: %s, argument: %s, packet: %s",
                    text,
                    match.group('unit_id').decode(),
                    match.group('channel').decode(),
                    command,
                    match.group('argument').decode(),
                    match.group(0),
                )

    def _log_queue_pressure(self) -> None:
        """Log current write-queue utilization."""
        queue_size = self._write_queue.qsize()
        queue_percent = queue_size / self._queue_size * 100
        if queue_percent >= 80:
            _LOGGER.warning(
                "RF command queue is %.0f%% full (%d/%d commands waiting). "
                "Commands are being sent faster than they can be transmitted (%.1fs per command).",
                queue_percent, queue_size, self._queue_size, COMMUNICATION_TIMEOUT,
            )
        elif queue_percent >= 50:
            _LOGGER.info(
                "RF command queue is %.0f%% full (%d/%d commands waiting)",
                queue_percent, queue_size, self._queue_size,
            )
        else:
            _LOGGER.debug(
                "Queueing RF command (queue: %d/%d, %.0f%% full)",
                queue_size, self._queue_size, queue_percent,
            )

    async def async_send(self, packet: bytes) -> None:
        """Enqueue packet without blocking the asyncio event loop."""
        if not self.is_alive():
            raise BeckerConnectionError("Error BeckerCommunicator thread not alive.")

        self._log_queue_pressure()
        max_attempts = max(1, self._retry_max + 1)
        for attempt in range(max_attempts):
            try:
                self._write_queue.put_nowait(packet)
                if attempt > 0:
                    _LOGGER.info("RF command queued after %d retry attempt(s)", attempt)
                return
            except queue.Full as err:
                if attempt < max_attempts - 1:
                    _LOGGER.warning(
                        "Queue full, retrying in %.1fs... (attempt %d/%d, queue: %d/%d)",
                        self._retry_delay, attempt + 1, max_attempts,
                        self._write_queue.qsize(), self._queue_size,
                    )
                    await asyncio.sleep(self._retry_delay)
                else:
                    _LOGGER.error(
                        "RF command queue is FULL after %d attempts (%d commands waiting); dropping command without stopping communicator.",
                        max_attempts, self._queue_size,
                    )
                    raise BeckerConnectionError(
                        f"Error sending packet after {max_attempts} attempts: queue full ({self._queue_size} waiting)."
                    ) from err

    def send(self, packet: bytes) -> None:
        """Synchronously enqueue packet (CLI / legacy callers)."""
        if not self.is_alive():
            raise BeckerConnectionError("Error BeckerCommunicator thread not alive.")
        self._log_queue_pressure()
        try:
            self._write_queue.put_nowait(packet)
        except queue.Full as err:
            raise BeckerConnectionError(
                f"Error sending packet: queue full ({self._queue_size} commands waiting)."
            ) from err

    def close(self) -> None:
        """Stop thread and close device"""
        self.stop()
        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=5)
        with self._io_lock:
            self._connection.close()
