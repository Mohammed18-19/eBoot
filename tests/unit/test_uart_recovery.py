import hashlib
import importlib.util
import struct
import sys
import types
import uuid
from pathlib import Path


UART_RECOVERY_PATH = Path(__file__).resolve().parents[2] / "tools" / "uart_recovery.py"


class FakeSerial:
    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.writes = []
        self.closed = False
        self.timeout = 5.0          # settable, like serial.Serial.timeout

    def read(self, size):
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def write(self, data):
        self.writes.append(bytes(data))
        return len(data)

    def close(self):
        self.closed = True


def load_uart_recovery_module(monkeypatch, fake_serial):
    serial_module = types.ModuleType("serial")
    serial_module.Serial = lambda *args, **kwargs: fake_serial
    monkeypatch.setitem(sys.modules, "serial", serial_module)

    module_name = f"uart_recovery_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, UART_RECOVERY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.time, "sleep", lambda _: None)
    return module


def test_auth_success_sends_expected_digest(monkeypatch):
    secret = bytes(range(32))
    challenge = bytes(range(32, 64))
    fake_serial = FakeSerial(bytes([0xAA]) + challenge + bytes([0xAA]))
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)

    client = uart_recovery.RecoveryClient("dummy-port")

    assert client.authenticate(secret.hex()) is True
    assert fake_serial.writes[0] == struct.pack(
        "<BBHI", uart_recovery.CMD_AUTH, 0, 0, 0
    )
    assert fake_serial.writes[1] == hashlib.sha256(challenge + secret).digest()


def test_auth_rejects_invalid_secret_length(monkeypatch, capsys):
    fake_serial = FakeSerial()
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)

    client = uart_recovery.RecoveryClient("dummy-port")

    assert client.authenticate("00") is False
    assert fake_serial.writes == []
    assert "exactly 32 bytes" in capsys.readouterr().out


def test_log_decodes_readable_entries(monkeypatch, capsys):
    payload = b"".join(
        [
            struct.pack("<IIII", 100, 0x01, 0, 0),
            struct.pack("<IIII", 200, 0x21, 0xFF, 3),
        ]
    )
    header = bytes([0xAA]) + struct.pack("<H", 2)
    fake_serial = FakeSerial(header + payload)
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)

    client = uart_recovery.RecoveryClient("dummy-port")

    assert client.read_boot_log(0, 2) is True
    output = capsys.readouterr().out
    assert "BOOT_START" in output
    assert "AUTH_FAIL" in output
    assert "slot=A" in output
    assert "slot=NONE" in output


def test_log_rejects_incomplete_payload(monkeypatch, capsys):
    payload = struct.pack("<IIII", 100, 0x01, 0, 0)
    header = bytes([0xAA]) + struct.pack("<H", 2)
    fake_serial = FakeSerial(header + payload)
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)

    client = uart_recovery.RecoveryClient("dummy-port")

    assert client.read_boot_log(0, 2) is False
    assert "Incomplete log response" in capsys.readouterr().out


def test_info_decodes_the_packed_22_byte_response(monkeypatch, capsys):
    """The firmware sends ack, five little-endian uint32 and a caps byte, packed:
    22 bytes, and nothing after. The client reads those, probes for surplus
    bytes (which would mean pre-fix firmware -- see the 24-byte test), finds
    none, and decodes the geometry from the same offsets test_recovery.c
    asserts the firmware writes them at."""
    payload = (bytes([0xAA])
               + struct.pack("<IIIII", 128 * 1024, 0x4000, 0x1000, 0x6000, 0x1000)
               + bytes([0x01 | 0x02]))          # caps: RNG and OTP
    assert len(payload) == 22
    fake_serial = FakeSerial(payload)
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)
    client = uart_recovery.RecoveryClient("dummy-port")

    assert client.info() is True
    assert bytes(fake_serial.incoming) == b"", "the response was not consumed whole"
    out = capsys.readouterr().out
    assert "Flash size:  128K" in out
    assert "Slot A:      0x00004000 (4K)" in out
    assert "Slot B:      0x00006000 (4K)" in out
    assert "Entropy:     yes" in out
    assert "OTP:         yes" in out


def test_info_names_a_board_with_no_entropy_source(monkeypatch, capsys):
    payload = bytes([0xAA]) + struct.pack("<IIIII", 1, 2, 3, 4, 5) + bytes([0x02])  # OTP only
    fake_serial = FakeSerial(payload)
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)
    client = uart_recovery.RecoveryClient("dummy-port")
    assert client.info() is True
    out = capsys.readouterr().out
    assert "authenticated recovery is unavailable" in out
    assert "OTP:         yes" in out


def test_info_refuses_the_24_byte_response_of_pre_fix_firmware(monkeypatch, capsys):
    """Firmware before the packed-struct fix sends 24 bytes: ack, three bytes
    of uninitialised padding, five fields. read(22) of that succeeds, and a
    client that then decodes it prints the leaked padding as the flash size,
    every address one word off, and a capability byte invented from a
    slot-size byte -- the exact defect this tool is meant to have stopped
    showing. It must recognise the legacy length, say so, and leave the
    serial buffer empty for the next command."""
    legacy = (bytes([0xAA, 0xA5, 0xA5, 0xA5])                       # ack + leaked padding
              + struct.pack("<IIIII", 128 * 1024, 0x4000, 0x1000, 0x6000, 0x1000))
    assert len(legacy) == 24
    fake_serial = FakeSerial(legacy)
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)
    client = uart_recovery.RecoveryClient("dummy-port")

    assert client.info() is False
    out = capsys.readouterr().out
    assert "pre-fix firmware" in out and "24 bytes" in out
    assert "10601K" not in out, "the leaked padding was printed as the flash size"
    assert "Entropy:" not in out, "a capability was invented from a geometry byte"
    assert bytes(fake_serial.incoming) == b"", "surplus bytes left to desync the next command"
    assert fake_serial.timeout == 5.0, "the probe's short timeout must be restored"


def test_info_probe_restores_the_timeout_on_the_good_path(monkeypatch):
    payload = bytes([0xAA]) + struct.pack("<IIIII", 1, 2, 3, 4, 5) + bytes([0x03])
    fake_serial = FakeSerial(payload)
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)
    client = uart_recovery.RecoveryClient("dummy-port")
    assert client.info() is True
    assert fake_serial.timeout == 5.0


def test_info_refuses_a_short_response(monkeypatch, capsys):
    """No firmware ever sent 21 bytes -- that was only ever what the client
    READ. This pins the truncated-read case; the legacy 24-byte case is the
    test above."""
    fake_serial = FakeSerial(bytes([0xAA]) + bytes(20))
    uart_recovery = load_uart_recovery_module(monkeypatch, fake_serial)
    client = uart_recovery.RecoveryClient("dummy-port")
    assert client.info() is False
    assert "Failed to get device info" in capsys.readouterr().out
