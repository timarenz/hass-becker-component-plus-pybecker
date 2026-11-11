"""Unit tests for Becker USB resilience, kernel USB reset, and unique_id migration."""

import asyncio
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

# Provide a lightweight pyserial stub if pyserial is not installed in the local test runner
try:
    import serial  # noqa: F401
    import serial.tools.list_ports  # noqa: F401
except ImportError:
    serial_mod = types.ModuleType("serial")

    class SerialException(OSError):
        pass

    class SerialTimeoutException(SerialException):
        pass

    serial_mod.SerialException = SerialException
    serial_mod.SerialTimeoutException = SerialTimeoutException
    serial_mod.serial_for_url = mock.MagicMock()

    tools_mod = types.ModuleType("serial.tools")
    list_ports_mod = types.ModuleType("serial.tools.list_ports")
    list_ports_mod.comports = lambda: []
    tools_mod.list_ports = list_ports_mod
    serial_mod.tools = tools_mod

    sys.modules["serial"] = serial_mod
    sys.modules["serial.tools"] = tools_mod
    sys.modules["serial.tools.list_ports"] = list_ports_mod

import serial  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pybecker import becker_helper as bh  # noqa: E402


class FakeSerial:
    """Minimal controllable pyserial double."""

    def __init__(self, fail_open=False, fail_write_once=False, fail_read=False):
        self.is_open = False
        self.fail_open = fail_open
        self.fail_write_once = fail_write_once
        self.fail_read = fail_read
        self.written = []
        self.closed_count = 0

    def open(self):
        if self.fail_open:
            raise serial.SerialException("cannot open")
        self.is_open = True

    def close(self):
        self.closed_count += 1
        self.is_open = False

    def write(self, data):
        if not self.is_open:
            raise serial.SerialException("port not open")
        if self.fail_write_once:
            self.fail_write_once = False
            raise serial.SerialTimeoutException("Write timeout")
        self.written.append(data)
        return len(data)

    def read(self, _size=1024):
        if self.fail_read:
            raise OSError(5, "Input/output error")
        return b""


class TestBeckerUSBResilience(unittest.TestCase):
    """Verify serial hardening, USBDEVFS_RESET recovery, and communicator safety."""

    def test_missing_device_at_boot_does_not_raise_and_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            dev_path = f"{tmp}/dev/serial/by-id/usb-Becker-stick"
            serial_objs = [FakeSerial(), FakeSerial()]
            with mock.patch("serial.serial_for_url", side_effect=serial_objs) as sfu:
                conn = bh.BeckerConnection(dev_path)
                self.assertTrue(conn.is_serial)
                self.assertFalse(conn.is_open)
                # Repeated reads while unplugged do not crash or open missing path
                self.assertEqual(conn.read(), b"")
                self.assertEqual(conn.read(), b"")

                # Verify write_timeout and exclusive were configured on POSIX
                _, kwargs = sfu.call_args
                self.assertEqual(kwargs["write_timeout"], bh.BeckerConnection.WRITE_TIMEOUT)
                if bh.os.name == "posix":
                    self.assertTrue(kwargs.get("exclusive"))

                # Simulate hot-plug creation of symlink
                Path(dev_path).parent.mkdir(parents=True, exist_ok=True)
                Path(dev_path).write_text("", encoding="utf-8")
                self.assertEqual(conn.read(), b"")
                self.assertTrue(conn.is_open)

    def test_socket_device_omits_exclusive(self):
        fake = FakeSerial()
        with mock.patch("serial.serial_for_url", return_value=fake) as sfu:
            conn = bh.BeckerConnection("192.168.1.50:5000")
            self.assertFalse(conn.is_serial)
            self.assertEqual(conn.device, "socket://192.168.1.50:5000")
            _, kwargs = sfu.call_args
            self.assertNotIn("exclusive", kwargs)

    def test_write_timeout_triggers_usbdevfs_reset_after_close_and_retries_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dev_path = root / "dev" / "ttyACM0"
            dev_path.parent.mkdir(parents=True)
            dev_path.write_text("", encoding="utf-8")

            sys_usb = root / "sys_usb" / "1-3"
            sys_usb.mkdir(parents=True)
            (sys_usb / "idVendor").write_text("2638\n", encoding="utf-8")
            (sys_usb / "idProduct").write_text("0013\n", encoding="utf-8")
            (sys_usb / "busnum").write_text("1\n", encoding="utf-8")
            (sys_usb / "devnum").write_text("4\n", encoding="utf-8")

            dev_bus_usb = root / "dev_bus_usb"
            usb_node = dev_bus_usb / "001" / "004"
            usb_node.parent.mkdir(parents=True)
            usb_node.write_bytes(b"")

            first_serial = FakeSerial(fail_write_once=True)
            second_serial = FakeSerial()
            events = []

            orig_close = first_serial.close

            def record_close():
                events.append("serial_closed")
                orig_close()

            first_serial.close = record_close

            def fake_ioctl(fd, op, arg):
                events.append(("ioctl", op, arg))
                return 0

            with (
                mock.patch.object(bh, "SYSFS_USB_PATH", root / "sys_usb"),
                mock.patch.object(bh, "SYSFS_TTY_PATH", root / "sys_tty"),
                mock.patch.object(bh, "DEV_BUS_USB_PATH", dev_bus_usb),
                mock.patch.object(bh, "ioctl", fake_ioctl),
                mock.patch.object(bh.BeckerConnection, "USB_POST_RESET_SETTLE", 0.0),
                mock.patch("serial.serial_for_url", side_effect=[first_serial, second_serial]),
            ):
                conn = bh.BeckerConnection(str(dev_path))
                pkt = b"\x02TEST\x03"
                conn.write(pkt)

                # Ensure serial fd was closed BEFORE USBDEVFS_RESET ioctl ran
                self.assertEqual(events[0], "serial_closed")
                self.assertEqual(events[1], ("ioctl", bh.USBDEVFS_RESET, 0))
                # Ensure packet was retried and delivered on rebuilt serial instance
                self.assertEqual(second_serial.written, [pkt])

    def test_communicator_survives_callback_error_and_queue_full(self):
        fake = FakeSerial()
        valid_code = bh.generate_code(1, ["8F57B", 1, 1], 0x20)
        valid_frame = bh.finalize_code(valid_code)

        calls = []

        def boom_callback(_match):
            calls.append(1)
            raise RuntimeError("boom in callback")

        with mock.patch("serial.serial_for_url", return_value=fake):
            comm = bh.BeckerCommunicator(
                "127.0.0.1:5000",
                callback=boom_callback,
                queue_size=1,
                retry_max=1,
                retry_delay=0.01,
            )
            comm.start()
            try:
                # Feed garbage > MAX_READ_BUFFER followed by a valid frame
                comm._read_buffer = (b"X" * (bh.MAX_READ_BUFFER + 500)) + valid_frame
                comm._parse()  # raises RuntimeError if called directly
            except RuntimeError:
                pass
            self.assertEqual(len(calls), 1)
            self.assertTrue(comm.is_alive())

            # Pause dequeuing briefly so queue fills and verify async_send does NOT stop thread
            comm._timeout = time.time() + 10.0
            asyncio.run(comm.async_send(b"pkt1"))
            with self.assertRaises(bh.BeckerConnectionError):
                asyncio.run(comm.async_send(b"pkt2"))
            self.assertTrue(comm.is_alive())
            comm._write_queue.get_nowait()
            comm.close()
            self.assertFalse(comm.is_alive())

    def test_cover_unique_id_migration_and_immutability(self):
        """Ensure v0.3.7 channel unique_ids migrate in-place and stay immutable when HA renames entity_id."""
        # Stub minimal homeassistant modules so cover.py can be imported standalone
        ha_mods = {}
        for mod_name in (
            "homeassistant",
            "homeassistant.components",
            "homeassistant.components.cover",
            "homeassistant.const",
            "homeassistant.core",
            "homeassistant.exceptions",
            "homeassistant.helpers",
            "homeassistant.helpers.config_validation",
            "homeassistant.helpers.entity_registry",
            "homeassistant.helpers.event",
            "homeassistant.helpers.restore_state",
            "homeassistant.helpers.dispatcher",
            "voluptuous",
        ):
            ha_mods[mod_name] = types.ModuleType(mod_name)

        class DummyCoverEntity:
            entity_id = None

            def async_schedule_update_ha_state(self):
                pass

        class DummyRestoreEntity:
            pass

        class DummyFeature:
            OPEN = 1
            CLOSE = 2
            STOP = 4
            OPEN_TILT = 8
            CLOSE_TILT = 16
            SET_POSITION = 32

        ha_mods["homeassistant.components.cover"].ATTR_CURRENT_POSITION = "current_position"
        ha_mods["homeassistant.components.cover"].ATTR_POSITION = "position"
        ha_mods["homeassistant.components.cover"].PLATFORM_SCHEMA = mock.MagicMock()
        ha_mods["homeassistant.components.cover"].CoverEntity = DummyCoverEntity
        ha_mods["homeassistant.components.cover"].CoverEntityFeature = DummyFeature

        ha_mods["homeassistant.const"].CONF_COVERS = "covers"
        ha_mods["homeassistant.const"].CONF_DEVICE = "device"
        ha_mods["homeassistant.const"].CONF_FILENAME = "filename"
        ha_mods["homeassistant.const"].CONF_FRIENDLY_NAME = "friendly_name"
        ha_mods["homeassistant.const"].CONF_VALUE_TEMPLATE = "value_template"
        ha_mods["homeassistant.const"].EVENT_HOMEASSISTANT_STOP = "homeassistant_stop"
        ha_mods["homeassistant.const"].STATE_CLOSED = "closed"
        ha_mods["homeassistant.const"].STATE_OPEN = "open"

        ha_mods["homeassistant.core"].callback = lambda fn: fn
        ha_mods["homeassistant.exceptions"].TemplateError = Exception
        ha_mods["homeassistant.exceptions"].HomeAssistantError = Exception

        cv = ha_mods["homeassistant.helpers.config_validation"]
        for attr in ("string", "template", "positive_float", "positive_int", "boolean"):
            setattr(cv, attr, object())
        cv.schema_with_slug_keys = lambda s: s

        vol = ha_mods["voluptuous"]
        vol.Schema = lambda x: mock.MagicMock()
        vol.Optional = lambda *a, **kw: a[0]
        vol.Required = lambda *a, **kw: a[0]
        vol.All = lambda *a: a
        vol.Range = lambda **kw: kw
        vol.Coerce = lambda x: x
        vol.In = lambda x: x

        ha_mods["homeassistant.helpers.event"].TrackTemplate = object
        ha_mods["homeassistant.helpers.event"].async_call_later = lambda *a: (lambda: None)
        ha_mods["homeassistant.helpers.event"].async_track_template_result = mock.MagicMock()
        ha_mods["homeassistant.helpers.restore_state"].RestoreEntity = DummyRestoreEntity
        ha_mods["homeassistant.helpers.dispatcher"].async_dispatcher_connect = mock.MagicMock()
        ha_mods["homeassistant.helpers.dispatcher"].dispatcher_send = mock.MagicMock()

        registry = {("cover", "becker", "2:1"): "cover.dining_area_left"}

        class FakeEntReg:
            def async_get_entity_id(self, domain, platform, uid):
                return registry.get((domain, platform, uid))

            def async_update_entity(self, entity_id, *, new_unique_id):
                for k, v in list(registry.items()):
                    if v == entity_id:
                        del registry[k]
                registry[("cover", "becker", new_unique_id)] = entity_id

        fake_er = FakeEntReg()
        ha_mods["homeassistant.helpers.entity_registry"].async_get = lambda _hass: fake_er
        ha_mods["homeassistant.helpers"].entity_registry = ha_mods["homeassistant.helpers.entity_registry"]
        ha_mods["homeassistant.helpers"].config_validation = cv

        pkg_name = "becker_pkg_under_test"
        pkg = types.ModuleType(pkg_name)
        pkg.__path__ = [str(REPO_ROOT)]

        with mock.patch.dict(sys.modules, {**ha_mods, pkg_name: pkg}):
            import importlib

            cover_mod = importlib.import_module(f"{pkg_name}.cover")
            fake_becker = mock.MagicMock()
            fake_becker.init_unconfigured_unit = mock.AsyncMock()
            added = []

            hass = mock.MagicMock()
            config = {
                "device": None,
                "filename": None,
                "queue_size": 100,
                "command_retry_max": 3,
                "command_retry_delay": 1.0,
                "covers": {
                    "kitchen_cover_dining_room_left": {
                        "channel": "2:1",
                        "travelling_time_up": 23.9,
                        "travelling_time_down": 22.3,
                    }
                },
            }
            with mock.patch.object(cover_mod.PyBecker, "setup"), mock.patch.object(
                cover_mod.PyBecker, "becker", fake_becker
            ):
                asyncio.run(cover_mod.async_setup_platform(hass, config, added.extend))

            self.assertEqual(len(added), 1)
            ent = added[0]
            expected_uid = "becker_cover_2:1_cover.kitchen_cover_dining_room_left"
            self.assertEqual(ent.unique_id, expected_uid)
            # Legacy "2:1" registry entry migrated in-place keeping cover.dining_area_left
            self.assertEqual(
                registry.get(("cover", "becker", expected_uid)),
                "cover.dining_area_left",
            )
            self.assertIsNone(registry.get(("cover", "becker", "2:1")))
            # Simulate HA applying registry entity_id override and verify unique_id does NOT mutate
            ent.entity_id = "cover.dining_area_left"
            self.assertEqual(ent.unique_id, expected_uid)


if __name__ == "__main__":
    unittest.main()
