#!/usr/bin/env python3
"""
Analyze a packet log copied from docs/gs3/index.html ("로그 복사" button) and
say which parts of the GS3 glucose record actually change over time.

The question this answers: when the displayed glucose never changes, is that
because the parser is wrong, because the sensor keeps sending the same bytes,
or because packets were dropped / truncated so nothing new was stored?

Usage:
    python3 tools/gs3_log_analyze.py LOGFILE [LOGFILE ...] [--all] [--csv OUT.csv]
    python3 tools/gs3_log_analyze.py selftest

Lines understood (everything else is ignored):
    [12:34:56.789] ← FF31 wire 1b 14 02 01 00 ... | plain ... | glucose      (page log, preferred)
    [12:34:56.789] → FF32 askNewData start=1: 3e f6 ...                     (page log, writes)
    [12:34:56.789]    idx=5 t=... bytes=[404f00005aca0000] ...              (fallback: record bytes only)
    REC idx=846 t=1789163220 raw=80568a0bca5a0308                            ("기록 내보내기": every record, survives reloads)
    READING idx=845 t=1789163160 mmolx10=32 trend=0 gcwarn=1                 ("기록 내보내기": older rows without raw bytes)
    1b1402010000...                                                          (bare hex, one FF31 packet per line)

Decoding is done with tools/gs3_protocol.py, i.e. exactly the layout Juggluco
uses (interpretgs3.cpp: mmolLx10 = (r7<<2)|(r6>>6), trend = (r6>>3)&7).
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import struct
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gs3_protocol as g  # noqa: E402

CMD_NAMES = {0x01: "auth", 0x03: "timeSync", 0x0F: "activation", 0x13: "bindUser",
             0x14: "glucose", 0x15: "glucoseInfo", 0x88: "ketoneAdc", 0xF0: "deviceInfo"}

RE_TS = re.compile(r"^\[(\d\d:\d\d:\d\d(?:\.\d+)?)\]")
RE_WIRE = re.compile(r"←\s*FF31\s+wire\s+([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s*\|")
RE_WRITE = re.compile(r"→\s*FF32\s+(.*?):\s*([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s*$")
RE_IDX = re.compile(r"idx=(\d+)\s+t=(.*?)\s+[-\d.]+\s+mmol/L.*?bytes=\[([0-9a-fA-F]{16})\]")
RE_BARE = re.compile(r"^\s*([0-9a-fA-F]{2}(?:[\s:]?[0-9a-fA-F]{2}){3,})\s*$")
RE_REC = re.compile(r"\bREC idx=(\d+) t=(\d+) raw=([0-9a-fA-F]{16})\b")
RE_READING = re.compile(r"\bREADING idx=(\d+) t=(\d+) mmolx10=(\d+) trend=(\d+)(?: gcwarn=(\d))?")


def _hex(s: str) -> bytes:
    return bytes.fromhex(re.sub(r"[\s:]", "", s))


def _utc(t: int) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%m-%d %H:%M:%SZ")


class Analysis:
    def __init__(self) -> None:
        self.packets: list[tuple[str, g.Packet]] = []       # (log ts, packet) for FF31
        self.writes: list[tuple[str, str, bytes]] = []       # (log ts, label, plain)
        self.records: "OrderedDict[int, dict]" = OrderedDict()   # index -> row (last wins)
        self.fallback_only = False

    # ---------------- ingestion ----------------
    def feed_line(self, line: str) -> None:
        ts = (RE_TS.match(line) or [None, ""])[1] or ""
        m = RE_WIRE.search(line)
        if m:
            self.add_packet(ts, _hex(m.group(1)))
            return
        m = RE_WRITE.search(line)
        if m:
            self.writes.append((ts, m.group(1).strip(), g.rc4(_hex(m.group(2)))))
            return
        m = RE_REC.search(line)
        if m:
            idx, t, raw = int(m.group(1)), int(m.group(2)), _hex(m.group(3))
            if idx not in self.records:
                self.records[idx] = self._row(self._rec(idx, t, raw), ts, "export REC", raw)
            return
        m = RE_READING.search(line)
        if m:
            idx = int(m.group(1))
            if idx not in self.records:
                gc = int(m.group(5)) if m.group(5) is not None else None
                self.records[idx] = dict(index=idx, time=int(m.group(2)), log_ts=ts, src="export READING",
                                         mmol_x10=int(m.group(3)), mg_dl=int(round(int(m.group(3)) * 1.8)),
                                         trend=int(m.group(4)), gcwarn=gc, twarn=None, shedding=None,
                                         temp=None, fieldB=None, fieldD=None, raw="")
            return
        m = RE_IDX.search(line)
        if m:
            idx, tstr, raw = int(m.group(1)), m.group(2), _hex(m.group(3))
            if idx not in self.records:      # wire line (if any) already gave a better row
                self.records[idx] = self._row(self._rec(idx, 0, raw), ts, "idx-line " + tstr, raw)
            return
        m = RE_BARE.match(line)
        if m and not line.strip().startswith("["):
            self.add_packet(ts, _hex(m.group(1)))

    def add_packet(self, ts: str, data: bytes) -> None:
        pkt = g.parse_notification(data)
        self.packets.append((ts, pkt))
        if pkt.kind == "glucose":
            for i, r in enumerate(pkt.records):
                raw = pkt.plain[9 + i * 8: 17 + i * 8]
                self.records[r.index] = self._row(r, ts, f"pkt start={pkt.start_index} n={len(pkt.records)} rem={pkt.remaining}", raw)

    @staticmethod
    def _rec(index: int, time: int, raw: bytes) -> g.GlucoseRecord:
        b9, ba, bf, b10 = raw[0], raw[1], raw[6], raw[7]
        return g.GlucoseRecord(index=index, time=time, mmol_x10=(b10 << 2) | (bf >> 6), trend=(bf >> 3) & 7,
                               temp_raw=(ba << 2) | (b9 >> 6), dump=struct.unpack_from("<H", raw, 2)[0],
                               current=struct.unpack_from("<H", raw, 4)[0], gcwarn=bf & 1, twarn=b9 & 1,
                               shedding=(b9 >> 1) & 1)

    @staticmethod
    def _row(r: g.GlucoseRecord, ts: str, src: str, raw: bytes | None = None) -> dict:
        row = dict(index=r.index, time=r.time, log_ts=ts, src=src, mmol_x10=r.mmol_x10, mg_dl=r.mg_dl,
                   trend=r.trend, gcwarn=r.gcwarn, twarn=r.twarn, shedding=r.shedding, temp=r.temp_raw,
                   fieldB=r.dump, fieldD=r.current, raw=raw.hex() if raw else "")
        if raw:
            for k in range(8):
                row[f"r{k}"] = raw[k]
            for off in (0, 2, 4, 6):
                row[f"u16le@{off}"] = struct.unpack_from("<H", raw, off)[0]
        return row

    # ---------------- reporting ----------------
    def report(self, show_all: bool = False) -> list[str]:
        out: list[str] = []
        kinds = Counter(p.kind for _, p in self.packets)
        out.append("== FF31 패킷 요약 ==")
        if not self.packets and not self.records:
            out.append("  인식된 패킷/레코드가 없습니다. 페이지의 '로그 복사' 결과 전체를 파일로 저장해 넘겨주세요.")
            return out
        out.append("  " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())) if kinds else "  (wire 라인 없음, idx= 라인만 사용)")
        acks = Counter((p.cmd, p.ack_result, p.ack_error) for _, p in self.packets if p.kind == "ack")
        for (cmd, res, err), n in sorted(acks.items()):
            out.append(f"  ACK cmd=0x{cmd:02X} ({CMD_NAMES.get(cmd, '?')}) result={res} error={err} ×{n}")
        others = [(ts, p) for ts, p in self.packets if p.kind in ("device_info", "info", "unknown")]
        for ts, p in others[:20]:
            n = p.plain[0]
            out.append(f"  [{ts}] cmd=0x{p.cmd:02X} {CMD_NAMES.get(p.cmd, p.kind)} sub/payload={p.plain[2:n].hex()}  {p.note}")
        bad = [(ts, p) for ts, p in self.packets if p.kind == "bad"]
        trunc = [(ts, p) for ts, p in bad if len(p.plain) >= 1 and p.plain[0] >= len(p.plain)]
        if bad:
            out.append(f"  !! 체크섬 불일치 패킷 {len(bad)}개, 그중 길이필드>수신길이(MTU 잘림 의심) {len(trunc)}개")
            for ts, p in bad[:8]:
                out.append(f"     [{ts}] len필드={p.plain[0] if p.plain else '-'} 수신={len(p.plain)} cmd=0x{p.cmd:02X} plain[:12]={p.plain[:12].hex()}")

        if self.writes:
            out.append("== FF32 쓰기 타임라인 ==")
            for ts, label, plain in self.writes[:60]:
                cmd = plain[1] if len(plain) > 1 else -1
                extra = ""
                if cmd == 0x14 and len(plain) >= 6:
                    extra = f" start={struct.unpack_from('<H', plain, 2)[0]} end={struct.unpack_from('<H', plain, 4)[0]}"
                elif cmd in (0x03, 0x0F) and len(plain) >= 6:
                    extra = f" time={struct.unpack_from('<I', plain, 2)[0]} ({_utc(struct.unpack_from('<I', plain, 2)[0])})"
                out.append(f"  [{ts}] {label}: cmd=0x{cmd:02X} {CMD_NAMES.get(cmd, '?')}{extra}")
            if len(self.writes) > 60:
                out.append(f"  ... {len(self.writes) - 60}개 더")

        rows = [self.records[i] for i in sorted(self.records)]
        out.append(f"== 혈당 레코드: {len(rows)}개 (index {rows[0]['index']}..{rows[-1]['index']}) ==" if rows else "== 혈당 레코드 없음 ==")
        if not rows:
            return out
        gl = [self._gl_pkt(p) for _, p in self.packets if p.kind == "glucose"]
        if gl:
            out.append(f"  0x14 패킷 {len(gl)}개: count 분포 {dict(Counter(c for c, *_ in gl))}, remaining>0 인 패킷 {sum(1 for c, r in gl if r)}개")
        head = ["idx", "sensor time(UTC)", "log", "mmol", "mg/dL", "tr", "gc/tw/sh", "temp", "fieldB", "fieldD", "raw r0..r7"]
        fmt = "  {:>6} {:>15} {:>12} {:>5} {:>5} {:>2} {:>8} {:>5} {:>6} {:>6}  {}"
        out.append(fmt.format(*head))
        shown = rows if (show_all or len(rows) <= 60) else [r for r in rows if r["index"] % 5 == 0]
        if shown is not rows:
            out.append(f"  (index%5==0 인 {len(shown)}개만 표시, 전부 보려면 --all)")
        d = lambda v: "-" if v is None else v  # noqa: E731
        for r in shown:
            out.append(fmt.format(r["index"], _utc(r["time"]) if r["time"] else "-", r["log_ts"][:12],
                                  f"{r['mmol_x10'] / 10:.1f}", r["mg_dl"], r["trend"],
                                  f"{d(r['gcwarn'])}/{d(r['twarn'])}/{d(r['shedding'])}", d(r["temp"]), d(r["fieldB"]), d(r["fieldD"]), r["raw"] or "-"))

        out.append("== 필드별 변동 (값이 하나뿐이면 '고정') ==")
        fields = ["mmol_x10", "trend", "gcwarn", "twarn", "shedding", "temp", "fieldB", "fieldD"]
        if any(r.get("raw") for r in rows):
            fields += [f"r{k}" for k in range(8)] + [f"u16le@{o}" for o in (0, 2, 4, 6)]
        for f in fields:
            vals = [r[f] for r in rows if r.get(f) is not None]
            if not vals:
                continue
            d = sorted(set(vals))
            tag = "고정" if len(d) == 1 else f"{len(d)}가지"
            out.append(f"  {f:10s} {tag:6s} min={min(vals):6d} max={max(vals):6d} first={vals[0]:6d} last={vals[-1]:6d}"
                       + (f"  values={d}" if 1 < len(d) <= 8 else ""))

        out.append("== 판정 ==")
        out.extend(self._verdict(rows))
        return out

    @staticmethod
    def _gl_pkt(p: g.Packet) -> tuple[int, int]:
        return len(p.records), p.remaining

    def _verdict(self, rows: list[dict]) -> list[str]:
        v: list[str] = []
        idxs = [r["index"] for r in rows]
        span_min = idxs[-1] - idxs[0]
        gls = [r["mmol_x10"] for r in rows]
        five = [r for r in rows if r["index"] % 5 == 0]
        gl5 = [r["mmol_x10"] for r in five]
        if all(x == 0 for x in gls):
            v.append(f"- 혈당 필드가 전부 0 (레코드 {len(rows)}개, {span_min}분). 센서가 아직 혈당을 내지 않는 상태(웜업/미측정). 파서 문제 아님.")
        elif len(rows) < 3 or span_min < 10:
            v.append(f"- 레코드가 {len(rows)}개({span_min}분)뿐이라 변동 여부를 판정할 수 없습니다. 페이지의 '기록 내보내기' 로 저장된 전체 기록을 붙여 넣어 주세요.")
        elif len(set(gl5)) == 1 and len(five) >= 3:
            hrs = (five[-1]["index"] - five[0]["index"]) / 60
            v.append(f"- index%5==0 레코드 {len(five)}개({hrs:.1f}시간)에서 혈당 바이트(r7, r6 상위 2비트)가 {gl5[0]/10:.1f} mmol/L "
                     f"= {five[0]['mg_dl']} mg/dL 로 완전 고정. 이 바이트 자체가 안 변하므로 파서가 아니라 센서 출력이 고정된 것.")
            moving = [f for f in ("fieldB", "fieldD", "temp", "trend") if len({r[f] for r in rows if r.get(f) is not None}) > 1]
            v.append(f"  같은 기간에 변한 필드: {', '.join(moving) or '없음'}")
        else:
            where = Counter(b["index"] % 5 for a, b in zip(rows, rows[1:])
                            if b["index"] == a["index"] + 1 and a["mmol_x10"] != b["mmol_x10"])
            v.append(f"- 혈당 값이 변합니다 ({len(set(gl5))}가지, index%5==0 기준). 연속 index 에서 값이 바뀐 위치의 index%5 분포: {dict(sorted(where.items()))} "
                     f"(Juggluco 문서: 센서는 1분마다 보내지만 5번은 같은 값 → 한 residue 에만 몰려 있으면 정상).")
        gc_known = [r for r in rows if r.get("gcwarn") is not None]
        if any(r["gcwarn"] for r in gc_known):
            n = sum(r["gcwarn"] for r in gc_known)
            v.append(f"- gcwarn(글루코스 경고 비트)=1 인 레코드 {n}/{len(gc_known)}개"
                     + (" — 센서가 모든 값에 경고를 붙이고 있음." if n == len(gc_known) else "."))
        if any(r.get("twarn") or r.get("shedding") for r in rows):
            v.append(f"- twarn/shedding 비트가 켜진 레코드 {sum(1 for r in rows if r.get('twarn') or r.get('shedding'))}개.")
        gaps = [(a + 1, b - 1) for a, b in zip(idxs, idxs[1:]) if b - a > 1]
        if gaps:
            v.append(f"- 빠진 index 구간 {len(gaps)}개: " + ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in gaps[:10])
                     + (" ..." if len(gaps) > 10 else ""))
        bad = [p for _, p in self.packets if p.kind == "bad" and p.plain and p.plain[0] >= len(p.plain)]
        if bad:
            v.append(f"- MTU 잘림으로 보이는 패킷 {len(bad)}개. 같은 start 로 재요청이 계속 잘리면 새 값이 저장되지 않아 표시가 멈춥니다.")
        times = [r["time"] for r in rows if r["time"]]
        if times and len(times) >= 2:
            per_idx = (times[-1] - times[0]) / max(1, idxs[-1] - idxs[0])
            if abs(per_idx - 60) > 5:
                v.append(f"- 주의: index 1당 센서 시각 증가가 {per_idx:.0f}초 (60초여야 정상).")
        return v

    def write_csv(self, path: str) -> None:
        rows = [self.records[i] for i in sorted(self.records)]
        keys = ["index", "time", "time_utc", "log_ts", "mmol_x10", "mg_dl", "trend", "gcwarn", "twarn", "shedding",
                "temp", "fieldB", "fieldD", "raw", "src"]
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(keys)
            for r in rows:
                r = dict(r, time_utc=_utc(r["time"]) if r["time"] else "")
                w.writerow([r.get(k, "") for k in keys])


def analyze_text(text: str) -> Analysis:
    a = Analysis()
    for line in text.splitlines():
        a.feed_line(line)
    return a


def selftest() -> None:
    def rec(mmol_x10: int, trend: int = 0, temp: int = 317, fb: int = 100, fd: int = 0x5ACA) -> bytes:
        r0 = ((temp & 3) << 6)
        r1 = temp >> 2
        r6 = ((mmol_x10 & 3) << 6) | (trend << 3)
        r7 = mmol_x10 >> 2
        return bytes([r0, r1]) + struct.pack("<H", fb) + struct.pack("<H", fd) + bytes([r6, r7])

    def pkt(start: int, t0: int, recs: list[bytes], remaining: int = 0) -> bytes:
        body = bytes([len(recs)]) + struct.pack("<HI", start, t0) + b"".join(recs) + struct.pack("<H", remaining)
        return g.rc4(g.frame(g.CMD_GLUCOSE, body))

    t0 = 1_757_600_000
    lines = ["[10:00:00.000] GS3 Web Reader ready",
             "[10:00:01.000] → FF32 askNewData start=1: " + " ".join(f"{b:02x}" for b in g.build_ask_data(1))]
    # frozen glucose 6.5 for 15 minutes, fieldB drifting
    for i in range(1, 16):
        lines.append(f"[10:{i:02d}:00.000] ← FF31 wire " + " ".join(f"{b:02x}" for b in pkt(i, t0 + i * 60, [rec(65, fb=100 + i)])) + " | plain .. | glucose")
    a = analyze_text("\n".join(lines))
    rep = "\n".join(a.report())
    assert "mmol_x10   고정" in rep and "fieldB     15가지" in rep, rep
    assert "완전 고정" in rep, rep
    # changing glucose in 5-minute blocks, one gap, one truncated packet
    lines = []
    for i in range(20, 41):
        if i == 30:
            continue
        val = 60 + (i // 5) * 3
        lines.append("← FF31 wire " + " ".join(f"{b:02x}" for b in pkt(i, t0 + i * 60, [rec(val, trend=1)])) + " | plain .. | glucose")
    full = pkt(41, t0 + 41 * 60, [rec(70)] * 3)
    lines.append("← FF31 wire " + " ".join(f"{b:02x}" for b in full[:20]) + " | plain .. | bad")
    a = analyze_text("\n".join(lines))
    rep = "\n".join(a.report(show_all=True))
    assert "혈당 값이 변합니다" in rep and "빠진 index 구간 1개: 30" in rep and "MTU 잘림" in rep, rep
    assert "index%5 분포: {0: 3}" in rep, rep
    # export formats: REC (raw) + READING (no raw), mixed with a wire line for the same index (wire wins)
    exp = ["--- EXPORT x raw=2 readings-only=1 ---",
           "REC idx=840 t=1789162860 raw=80568a0bca5a0308",
           "REC idx=845 t=1789163160 raw=80568a0bca5a0308",
           "READING idx=835 t=1789162560 mmolx10=32 trend=0 gcwarn=1",
           "READING idx=830 t=1789162260 mmolx10=32 trend=0",
           "--- END EXPORT ---"]
    a = analyze_text("\n".join(exp))
    rep = "\n".join(a.report(show_all=True))
    assert list(a.records) == [840, 845, 835, 830] and a.records[835]["temp"] is None, list(a.records)
    assert "완전 고정" in rep and "gcwarn(글루코스 경고 비트)=1 인 레코드 3/3개" in rep, rep
    # fallback idx-line parsing
    a = analyze_text("[11:00:00.000]    idx=45 t=11:00:00 6.5 mmol/L 117 mg/dL trend=0 temp=317 bytes=[404f64004aca0010] fieldB=100 fieldD=51786")
    assert list(a.records) == [45] and a.records[45]["mmol_x10"] == 64, a.records
    print("selftest OK")


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["selftest"]:
        selftest()
        return
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", nargs="+")
    ap.add_argument("--all", action="store_true", help="show every record, not only index%%5==0")
    ap.add_argument("--csv", help="also write all records to this CSV file")
    a = ap.parse_args(argv)
    an = Analysis()
    for path in a.logfile:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                an.feed_line(line.rstrip("\n"))
    print("\n".join(an.report(show_all=a.all)))
    if a.csv:
        an.write_csv(a.csv)
        print(f"\nCSV 저장: {a.csv}")


if __name__ == "__main__":
    main()
