#!/usr/bin/env python3
"""
Sibionics / SISENSING GS3 CGM  -  BLE protocol reference implementation.

Everything in this file is transcribed from the GPL-3.0 sources of Juggluco
(https://github.com/j-kaltes/Juggluco, files Common/src/main/cpp/sibionics3/
interpretgs3.cpp, sibionics/interpret_data.cpp, sibionics/handleData.cpp,
sibionics/makeWriteCharacter.cpp and Common/src/mobileSi/java/tk/glucodata/
Si3GattCallback.java).  Nothing here has been validated against a real GS3
sensor by the authors of this repository; see docs/gs3-ble-protocol-analysis.md
for what is confirmed-by-source versus inferred.

Usage:
    python3 tools/gs3_protocol.py selftest
    python3 tools/gs3_protocol.py vectors --mac E2:AF:F9:F0:1F:19 --account-id 2019091906067780457
    python3 tools/gs3_protocol.py decrypt 23F76FD9F4 24E76F34 ...
    python3 tools/gs3_protocol.py simulate --mac ... --account-id ...
"""
from __future__ import annotations

import argparse
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------
# Constants (all confirmed from Juggluco source)
# --------------------------------------------------------------------------

SERVICE_FF30 = "0000ff30-0000-1000-8000-00805f9b34fb"
CHAR_FF31_NOTIFY = "0000ff31-0000-1000-8000-00805f9b34fb"
CHAR_FF32_WRITE = "0000ff32-0000-1000-8000-00805f9b34fb"
SERVICE_DATA_UUID_5347 = "00005347-0000-1000-8000-00805f9b34fb"
MTU_REQUEST = 247

# sibionics/interpret_data.cpp:47  -  static RC4 key shared by GS1 (newSI) and GS3
RC4_KEY = bytes([0x01, 0x38, 0x0B, 0x9A, 0x00, 0x5B, 0x02, 0x5D,
                 0xCD, 0x9E, 0xC3, 0x99, 0x09, 0x37, 0xAA, 0xE8])

# sibionics/interpret_data.cpp getkey(): 16-byte "registered block" per official app,
# indexed by Juggluco's siType/siSubtype.
APP_KEYS = {
    0: b"THE544U0TYITE461",  # com.sisensing.sijoy        (GS1 international)
    1: b"LQSS54U0RURUA99J",  # com.sisensing.rusibionics  (GS1 Russia)
    2: b"GKSHGDU0TYA456G4",  # com.sisensing.sisensingcgm
    3: b"GKSHGDU0TYA456G4",  # com.sisensing.eco          (GS1 China)
    4: b"THE544U0TYITE461",  # com.sisensing.gs3          (GS3 international)  <- GS3*-BEANLA / SISENSING-GNL
    5: b"GKSHGDU0TYA456G4",  # com.sibionics.gstoc        (GS3 China, marked "Guess" in Juggluco)
}
SITYPE_GS3_INTL = 4
SITYPE_GS3_CN = 5

# command bytes (second byte of every plaintext frame)
CMD_AUTH = 0x01
CMD_TIME_SYNC = 0x03
CMD_ACTIVATION = 0x0F      # vendor name: v120_glouse_ketone_activation_nosens
CMD_BIND_USER = 0x13       # vendor name: v120_glouse_id_bound
CMD_GLUCOSE = 0x14         # vendor name: v120_gs3_raw_glouse_data (request) / glucose records (reply)
CMD_GLUCOSE_INFO = 0x15    # gs3_only_glouse_info (reply only, ignored by Juggluco)
CMD_KETONE_ADC = 0x88      # only_glouse_ketone_adc_info_t (reply only, ignored)
CMD_DEVICE_INFO = 0xF0     # request sub-command / reply sub-command

DEVICE_INFO_SUBS = {
    0x01: "u16 sensor reading",
    0x02: "u8 activation",
    0x03: "device time",
    0x04: "device storage",
    0x05: "device calibration (4 x uint32)",
    0x06: "secret key (16 bytes)",
    0x07: "device reset info",
    0x08: "glucose threshold",
    0x09: "oscillator",
    0x0A: "watchdog",
    0x0B: "glucose+ketone u16 sensor pair",
    0x0C: "life",
    0x0D: "device id (1 + 8 bytes)",
}

# The one frame that is always sent in plaintext: ACK for cmd 0x00 (= "not authenticated")
PLAINTEXT_HELLO = bytes([0x04, 0x00, 0x00, 0x00, 0xFC])

MG_DL_PER_MMOL = 18.0  # Juggluco: convfactordL = convfactor(180.0) * 0.1

GS3_TREND = {0: "flat", 1: "slightly up", 2: "up", 3: "slightly down", 4: "down"}
GS3_TREND_RATE_MMOL = {0: 0.0, 1: 1.05, 2: 4.0, 3: -1.05, 4: -4.0}


# --------------------------------------------------------------------------
# RC4 (sibionics/interpret_data.cpp Rc4XorWithKey, skip_count is always 0)
# --------------------------------------------------------------------------

def rc4(data: bytes, key: bytes = RC4_KEY) -> bytes:
    """Plain RC4. A fresh keystream is used for EVERY packet (no IV, no nonce,
    no counter), so encrypt == decrypt and every frame is XORed with the same
    keystream prefix."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# --------------------------------------------------------------------------
# Frame helpers
# --------------------------------------------------------------------------

def checksum(body: bytes) -> int:
    """Two's complement of the byte sum, so that sum(frame) == 0 mod 256."""
    return (-sum(body)) & 0xFF


def frame(cmd: int, payload: bytes = b"") -> bytes:
    """[len][cmd][payload...][checksum], len = number of bytes before checksum."""
    body = bytes([2 + len(payload), cmd]) + payload
    return body + bytes([checksum(body)])


def frame_is_valid(p: bytes) -> bool:
    n = p[0]
    return n >= 2 and n < len(p) and p[n] == checksum(p[:n])


def mac_to_bytes_le(mac: str) -> bytes:
    """'E2:AF:F9:F0:1F:19' -> b'\\x19\\x1f\\xf0\\xf9\\xaf\\xe2' (reversed, as deviceArray() does)."""
    parts = [int(x, 16) for x in mac.replace("-", ":").split(":")]
    if len(parts) != 6:
        raise ValueError("MAC must have 6 octets")
    return bytes(reversed(parts))


# --------------------------------------------------------------------------
# Outgoing commands (app -> FF32).  All are returned RC4-encrypted.
# --------------------------------------------------------------------------

def build_auth(mac: str, si_type: int = SITYPE_GS3_INTL, encrypt: bool = True) -> bytes:
    """v120_apply_authentication: 19 01 00 <mac LE 6> <app key 16> <cksum> (26 bytes)."""
    plain = frame(CMD_AUTH, bytes([0x00]) + mac_to_bytes_le(mac) + APP_KEYS[si_type])
    assert len(plain) == 26 and plain[0] == 0x19
    return rc4(plain) if encrypt else plain


def account_id_to_payload(account_id: int) -> bytes:
    """saveGS3id(): uint64 big-endian into gs3id[0..7], gs3id[8..11] stay zero."""
    return struct.pack(">Q", account_id) + bytes(4)


def build_bind_user(account_id: int, seq: int, encrypt: bool = True) -> bytes:
    """v120_glouse_id_bound: 0F 13 <seq> <12-byte id> <cksum> (16 bytes). seq is 1, then 2 on retry."""
    plain = frame(CMD_BIND_USER, bytes([seq]) + account_id_to_payload(account_id))
    assert len(plain) == 16 and plain[0] == 0x0F
    return rc4(plain) if encrypt else plain


def build_device_info(sub: int, encrypt: bool = True) -> bytes:
    """v120_device_information: 03 F0 <sub> <0x0D - sub> (4 bytes). Juggluco uses sub 1 and 7."""
    plain = frame(CMD_DEVICE_INFO, bytes([sub]))
    assert plain[3] == (0x0D - sub) & 0xFF
    return rc4(plain) if encrypt else plain


def build_activation(unix_seconds: int, encrypt: bool = True) -> bytes:
    """v120_glouse_ketone_activation_nosens: 06 0F <u32 LE time> <cksum> (7 bytes)."""
    plain = frame(CMD_ACTIVATION, struct.pack("<I", unix_seconds))
    return rc4(plain) if encrypt else plain


def build_time_sync(unix_seconds: int, encrypt: bool = True) -> bytes:
    """v120_isec_update (getSItimecmd): 06 03 <u32 LE time> <cksum> (7 bytes)."""
    plain = frame(CMD_TIME_SYNC, struct.pack("<I", unix_seconds))
    return rc4(plain) if encrypt else plain


def build_ask_data(start_index: int, end_index: int = 0, encrypt: bool = True) -> bytes:
    """v120_gs3_raw_glouse_data: 06 14 <u16 LE start> <u16 LE end> <cksum> (7 bytes).
    Juggluco always sends end=0 and start = last stored record index + 1 (or 1)."""
    plain = frame(CMD_GLUCOSE, struct.pack("<HH", start_index, end_index))
    return rc4(plain) if encrypt else plain


# --------------------------------------------------------------------------
# Incoming notifications (FF31 -> app)
# --------------------------------------------------------------------------

@dataclass
class GlucoseRecord:
    index: int              # minute counter since sensor start; index % 5 == 0 are the "official" values
    time: int               # unix seconds = start_time + i*60
    mmol_x10: int           # 10-bit glucose in 0.1 mmol/L
    trend: int              # 0 flat, 1 slightly up, 2 up, 3 slightly down, 4 down
    temp_raw: int           # 10-bit, unit unknown
    dump: int               # u16, meaning unknown (vendor field name "dump")
    current: int            # u16, vendor field "c1"/current (raw sensor current?)
    gcwarn: int
    twarn: int
    shedding: int

    @property
    def mmol(self) -> float:
        return self.mmol_x10 / 10.0

    @property
    def mg_dl(self) -> int:
        return int(round(self.mmol_x10 * 0.1 * MG_DL_PER_MMOL))


@dataclass
class Packet:
    raw_cipher: bytes
    plain: bytes
    kind: str                       # "hello" | "ack" | "glucose" | "device_info" | "info" | "bad" | "unknown"
    cmd: int = 0
    ack_result: int = 0             # ACK byte 2 ("reply_ack_resule")
    ack_error: int = 0              # ACK byte 3
    sub: int = 0                    # 0xF0 sub-command
    records: list = field(default_factory=list)
    start_index: int = 0
    start_time: int = 0
    remaining: int = 0              # last_reindex: records still to come; 0 = this batch ends at "now"
    note: str = ""


def parse_notification(data: bytes) -> Packet:
    """Mirror of gs3Glucose()'s decoding stage (interpretgs3.cpp)."""
    if len(data) == 5 and data[:4] == b"\x04\x00\x00\x00" and data[4] == 0xFC:
        return Packet(data, data, "hello", cmd=0, note="plaintext ACK(cmd 0): sensor not authenticated")
    p = rc4(data)
    if len(p) < 2:
        return Packet(data, p, "bad", note="too short")
    n, cmd = p[0], p[1]

    # 5-byte ACK form: [04][cmd][result][error][cksum]
    if n == 4 and len(p) >= 5:
        if p[4] != checksum(p[:4]):
            return Packet(data, p, "bad", cmd=cmd, note="ack checksum mismatch")
        return Packet(data, p, "ack", cmd=cmd, ack_result=p[2], ack_error=p[3])

    if not frame_is_valid(p):
        return Packet(data, p, "bad", cmd=cmd, note="checksum mismatch (wrong key? fragmented notify?)")

    if cmd == CMD_GLUCOSE:
        count = p[2]
        start_index = struct.unpack_from("<H", p, 3)[0]
        start_time = struct.unpack_from("<I", p, 5)[0]
        remaining = p[n - 2] | (p[n - 1] << 8)
        recs = []
        for i in range(count):
            r = p[9 + i * 8: 17 + i * 8]
            b9, ba, bf, b10 = r[0], r[1], r[6], r[7]
            recs.append(GlucoseRecord(
                index=start_index + i,
                time=start_time + i * 60,
                mmol_x10=(b10 << 2) | (bf >> 6),
                trend=(bf >> 3) & 7,
                temp_raw=(ba << 2) | (b9 >> 6),
                dump=struct.unpack_from("<H", r, 2)[0],
                current=struct.unpack_from("<H", r, 4)[0],
                gcwarn=bf & 1,
                twarn=b9 & 1,
                shedding=(b9 >> 1) & 1,
            ))
        return Packet(data, p, "glucose", cmd=cmd, records=recs, start_index=start_index,
                      start_time=start_time, remaining=remaining)

    if cmd == CMD_DEVICE_INFO:
        sub = p[2]
        return Packet(data, p, "device_info", cmd=cmd, sub=sub,
                      note=DEVICE_INFO_SUBS.get(sub, "unknown sub"))

    if cmd in (CMD_GLUCOSE_INFO, CMD_KETONE_ADC):
        return Packet(data, p, "info", cmd=cmd, note="ignored by Juggluco")

    return Packet(data, p, "unknown", cmd=cmd)


# --------------------------------------------------------------------------
# Handshake state machine (mirror of gs3Glucose()'s reply logic)
# --------------------------------------------------------------------------

@dataclass
class Gs3Session:
    mac: str
    account_id: int
    si_type: int = SITYPE_GS3_INTL
    next_index: int = 1            # last stored record index + 1
    now: callable = lambda: int(time.time())
    log: list = field(default_factory=list)

    def first_write(self) -> bytes:
        """What to write to FF32 right after the FF31 CCCD write succeeded."""
        self.log.append("auth")
        return build_auth(self.mac, self.si_type)

    def on_notify(self, data: bytes) -> tuple[Packet, Optional[bytes], Optional[str]]:
        """Returns (parsed packet, next bytes to write to FF32 or None, control event or None).
        control events: 'wrong_account_id' (disconnect), 'data_request_acked'."""
        pkt = parse_notification(data)
        if pkt.kind == "ack":
            t = ((pkt.cmd | 0xC000) + 1) & 0xFFFF
            if t == 0xC002:                       # ACK for 0x01 auth
                self.log.append("bindUser seq=1")
                return pkt, build_bind_user(self.account_id, 1), None
            if t == 0xC014:                       # ACK for 0x13 bind
                if pkt.ack_error == 0:
                    self.log.append("deviceinfo 1")
                    return pkt, build_device_info(1), None
                if pkt.ack_result == 2:
                    self.log.append("Wrong account ID")
                    return pkt, None, "wrong_account_id"
                self.log.append(f"bind error {pkt.ack_error}, bindUser seq=2")
                return pkt, build_bind_user(self.account_id, 2), None
            if t == 0xC010:                       # ACK for 0x0F activation/time
                self.log.append("time sync")
                return pkt, build_time_sync(self.now()), None
            if t == 0xC004:                       # ACK for 0x03 time sync
                self.log.append(f"askNewData {self.next_index}")
                return pkt, build_ask_data(self.next_index, 0), None
            if t == 0xC015:                       # ACK for 0x14 data request
                return pkt, None, "data_request_acked"
            return pkt, None, None
        if pkt.kind == "device_info":
            if pkt.sub == 0x01:
                self.log.append("deviceinfo 7")
                return pkt, build_device_info(7), None
            if pkt.sub == 0x07:
                self.log.append("activation(time)")
                return pkt, build_activation(self.now()), None
            return pkt, None, None
        if pkt.kind == "glucose":
            if pkt.records:
                self.next_index = pkt.records[-1].index + 1
            return pkt, None, None
        return pkt, None, None


# --------------------------------------------------------------------------
# Self test / CLI
# --------------------------------------------------------------------------

def selftest() -> None:
    # Two constants that Juggluco compares against real sensor traffic (GS1 code path);
    # they decrypt to well-formed frames only if the RC4 key above is right.
    assert rc4(bytes.fromhex("23F76FD9F4")) == PLAINTEXT_HELLO, "RC4 key mismatch (hello)"
    assert rc4(bytes.fromhex("24E76F34")) == bytes.fromhex("031000ED"), "RC4 key mismatch (reset)"
    assert frame_is_valid(bytes.fromhex("031000ED"))
    mac = "E2:AF:F9:F0:1F:19"
    aid = 2019091906067780457
    for plain in (build_auth(mac, encrypt=False), build_bind_user(aid, 1, encrypt=False),
                  build_device_info(1, encrypt=False), build_device_info(7, encrypt=False),
                  build_activation(1_700_000_000, encrypt=False),
                  build_time_sync(1_700_000_000, encrypt=False),
                  build_ask_data(1, 0, encrypt=False)):
        assert frame_is_valid(plain), plain.hex()
        assert rc4(rc4(plain)) == plain
    assert build_device_info(1, encrypt=False) == bytes.fromhex("03F0010C")
    assert build_device_info(7, encrypt=False) == bytes.fromhex("03F00706")
    assert build_ask_data(1, 0, encrypt=False) == bytes.fromhex("0614010000" "00E5")
    # synthetic glucose packet round trip: 2 records, index 60/61, 6.5 mmol/L, trend up
    recs = b""
    for mmol_x10, trend in ((65, 2), (66, 1)):
        bf = ((mmol_x10 & 3) << 6) | (trend << 3)
        b10 = mmol_x10 >> 2
        recs += bytes([0x00, 0x00, 0, 0, 0, 0, bf, b10])
    body = bytes([2]) + struct.pack("<HI", 60, 1_700_000_000) + recs + struct.pack("<H", 0)
    plain = frame(CMD_GLUCOSE, body)
    pkt = parse_notification(rc4(plain))
    assert pkt.kind == "glucose" and [r.mmol_x10 for r in pkt.records] == [65, 66]
    assert pkt.records[0].mg_dl == 117 and pkt.records[0].trend == 2 and pkt.records[1].time == 1_700_000_060
    # handshake walk-through
    s = Gs3Session(mac, aid, now=lambda: 1_700_000_000)
    s.first_write()
    for reply in (rc4(frame(0x01, b"\x00\x00")), rc4(frame(0x13, b"\x00\x00")),
                  rc4(frame(0xF0, b"\x01\x00\x00")), rc4(frame(0xF0, b"\x07" + bytes(9))),
                  rc4(frame(0x0F, b"\x00\x00")), rc4(frame(0x03, b"\x00\x00")),
                  rc4(frame(0x14, b"\x00\x00"))):
        s.on_notify(reply)
    assert s.log == ["auth", "bindUser seq=1", "deviceinfo 1", "deviceinfo 7", "activation(time)",
                     "time sync", "askNewData 1"], s.log
    print("selftest OK")


def cmd_vectors(a) -> None:
    now = a.time or int(time.time())
    print(f"# GS3 test vectors  mac={a.mac} account_id={a.account_id} siType={a.si_type} time={now}")
    rows = [
        ("auth (0x01)", build_auth(a.mac, a.si_type, encrypt=False)),
        ("bindUser seq1 (0x13)", build_bind_user(a.account_id, 1, encrypt=False)),
        ("bindUser seq2 (0x13)", build_bind_user(a.account_id, 2, encrypt=False)),
        ("deviceInfo 1 (0xF0)", build_device_info(1, encrypt=False)),
        ("deviceInfo 7 (0xF0)", build_device_info(7, encrypt=False)),
        ("activation/time (0x0F)", build_activation(now, encrypt=False)),
        ("time sync (0x03)", build_time_sync(now, encrypt=False)),
        (f"askNewData start={a.start} (0x14)", build_ask_data(a.start, 0, encrypt=False)),
    ]
    for name, plain in rows:
        print(f"{name:32s} plain={plain.hex()}\n{'':32s} wire ={rc4(plain).hex()}")


def cmd_decrypt(a) -> None:
    for h in a.hex:
        data = bytes.fromhex(h.replace(" ", "").replace(":", ""))
        pkt = parse_notification(data)
        print(f"wire ={data.hex()}\nplain={pkt.plain.hex()}  kind={pkt.kind} cmd=0x{pkt.cmd:02X} {pkt.note}")
        if pkt.kind == "ack":
            print(f"      ack result={pkt.ack_result} error={pkt.ack_error}")
        if pkt.kind == "glucose":
            print(f"      start_index={pkt.start_index} start_time={pkt.start_time} remaining={pkt.remaining}")
            for r in pkt.records:
                print(f"      idx={r.index:5d} t={r.time} {r.mmol:4.1f} mmol/L {r.mg_dl:3d} mg/dL "
                      f"trend={GS3_TREND.get(r.trend, r.trend)} temp_raw={r.temp_raw} current={r.current} "
                      f"dump={r.dump} warn(g/t/s)={r.gcwarn}/{r.twarn}/{r.shedding}")
        print()


def cmd_simulate(a) -> None:
    s = Gs3Session(a.mac, a.account_id, a.si_type)
    print("write FF32:", s.first_write().hex(), "  # auth")
    script = [
        ("ack auth", rc4(frame(0x01, b"\x00\x00"))),
        ("ack bind ok", rc4(frame(0x13, b"\x00\x00"))),
        ("F0/01", rc4(frame(0xF0, b"\x01\x34\x12"))),
        ("F0/07", rc4(frame(0xF0, b"\x07" + bytes(9)))),
        ("ack 0F", rc4(frame(0x0F, b"\x00\x00"))),
        ("ack 03", rc4(frame(0x03, b"\x00\x00"))),
        ("ack 14", rc4(frame(0x14, b"\x00\x00"))),
    ]
    for name, reply in script:
        pkt, out, ev = s.on_notify(reply)
        print(f"notify FF31 ({name}): {reply.hex()} -> plain {pkt.plain.hex()}")
        if out:
            print("write FF32:", out.hex(), " #", s.log[-1])
        if ev:
            print("event:", ev)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    v = sub.add_parser("vectors")
    v.add_argument("--mac", default="E2:AF:F9:F0:1F:19")
    v.add_argument("--account-id", type=int, default=2019091906067780457)
    v.add_argument("--si-type", type=int, default=SITYPE_GS3_INTL)
    v.add_argument("--start", type=int, default=1)
    v.add_argument("--time", type=int, default=0)
    d = sub.add_parser("decrypt")
    d.add_argument("hex", nargs="+")
    m = sub.add_parser("simulate")
    m.add_argument("--mac", default="E2:AF:F9:F0:1F:19")
    m.add_argument("--account-id", type=int, default=2019091906067780457)
    m.add_argument("--si-type", type=int, default=SITYPE_GS3_INTL)
    a = ap.parse_args(argv)
    {"selftest": lambda a: selftest(), "vectors": cmd_vectors,
     "decrypt": cmd_decrypt, "simulate": cmd_simulate}[a.cmd](a)


if __name__ == "__main__":
    main()
