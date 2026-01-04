#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于“短页停”策略的 TCP 拉取脚本：
- 建立 TCP（可选 SOCKS5）
- 可选先发送一个“HELLO/欢迎”请求（按需）
- 发送分页请求模板（仅替换日期与代码，不改变长度）
- 请求中的 offset 字段按固定步长递增
- 每轮接收以“静默阈值”聚合分片，作为一页响应
- 以“本页收到字节数明显小于首个标准页”为“末页”判定，自动停止（短页停）

适用你的场景：
- 你提供的第一个请求包作为模板（默认内置），仅替换日期与 code
- 你提供的小包作为“HELLO”（默认内置，可开启/关闭）
- 典型步长为 0x7530（30000）；你可通过 --step 调整
- offset 两个字段默认位置为 0x0C,0x10（如需可改）
"""
import argparse
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List
# 内置的“HELLO/欢迎”请求（来自你的示例）
DEFAULT_HELLO_HEXDUMP = """\
00 00 00 00  00 00 2a 00  2a 00 c5 02  68 69 73 68
66 2f 64 61  74 65 2f 32  30 32 35 30  36 31 32 2f
73 68 36 30  35 35 39 38  2e 69 6d 67  00 00 00 00
00 00 00 00
"""

DEFAULT_REQ_HEXDUMP = """\
00 00 00 00  00 00 36 01  36 01 b9 06  00 00 00 00
30 75 00 00  68 69 73 68  66 2f 64 61  74 65 2f 32
30 32 35 30  36 31 32 2f  73 68 36 30  35 35 39 38
2e 69 6d 67  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
"""




ASCII_PATTERN = re.compile(
    rb"hishf/date/(?P<date>\d{8})/(?P<market>[a-z]{2})(?P<code>\d{6})\.img"
)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_hexdump(text: str) -> bytes:
    hex_pairs = re.findall(r"\b[0-9A-Fa-f]{2}\b", text)
    return bytes.fromhex("".join(hex_pairs))

def load_payload_from_args(hexfile: Optional[str], binfile: Optional[str], fallback_hex: str) -> bytes:
    if hexfile:
        return parse_hexdump(Path(hexfile).read_text(encoding="utf-8"))
    if binfile:
        return Path(binfile).read_bytes()
    return parse_hexdump(fallback_hex)



def replace_date_code(raw: bytes, date: Optional[str], code: Optional[str]) -> bytes:
    if not any([date, code]):
        return raw
    def repl(m: re.Match) -> bytes:
        cur_date = m.group("date").decode()
        cur_code = m.group("code").decode()
        nd = date if date else cur_date
        nc = code if code else cur_code
        nm = "sh" if nc.startswith("6") else "sz"
        if not (len(nd) == 8 and len(nm) == 2 and len(nc) == 6):
            return m.group(0)
        seg = f"hishf/date/{nd}/{nm}{nc}.img".encode()
        return seg if len(seg) == len(m.group(0)) else m.group(0)
    new_raw, _ = ASCII_PATTERN.subn(repl, raw)
    return new_raw

def read_offset_le(payload: bytes, pos: int) -> int:
    if pos < 0 or pos + 4 > len(payload):
        raise ValueError(f"offset 位置越界: {pos}")
    return int.from_bytes(payload[pos:pos+4], "little")

def write_offset_le(payload: bytes, pos: int, value: int) -> bytes:
    if pos < 0 or pos + 4 > len(payload):
        raise ValueError(f"offset 位置越界: {pos}")
    out = bytearray(payload)
    out[pos:pos+4] = value.to_bytes(4, "little", signed=False)
    return bytes(out)

def connect(host: str, port: int, socks5: Optional[str], timeout: float) -> socket.socket:
    if socks5:
        hp, pp = socks5.split(":")
        try:
            import socks  # PySocks
        except ImportError:
            print("需要 PySocks：pip install pysocks", file=sys.stderr)
            sys.exit(2)
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, hp, int(pp))
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    return socket.create_connection((host, port), timeout=timeout)

def recv_until_quiet(sock: socket.socket, quiet_ms: int, bufsize: int = 65536) -> bytes:
    sock.setblocking(False)
    buf = bytearray()
    last = time.monotonic()
    while True:
        try:
            chunk = sock.recv(bufsize)
            if chunk:
                buf += chunk
                last = time.monotonic()
            else:
                break  # 对端关闭
        except (BlockingIOError, InterruptedError, socket.timeout):
            pass
        except Exception:
            break
        time.sleep(0.005)
        if (time.monotonic() - last) * 1000 >= quiet_ms:
            break
    sock.setblocking(True)
    return bytes(buf)

def hexdump(data: bytes, width: int = 16) -> str:
    lines: List[str] = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}:  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="短页停策略的 TCP 分页拉取（仅改日期与代码）")
    ap.add_argument("--host", default="120.237.21.226", help="目标主机")
    ap.add_argument("--port", type=int, default=7709, help="目标端口")
    ap.add_argument("--socks5", help="SOCKS5 代理，如 127.0.0.1:1080")

    # 载荷来源（可外部文件覆盖）
    ap.add_argument("--hello-hex", help="HELLO 请求的 hexdump 文本文件；未提供则使用内置默认")
    ap.add_argument("--hello-bin", help="HELLO 请求的二进制文件")
    ap.add_argument("--template-hex", help="分页请求模板的 hexdump 文本文件；未提供则使用内置默认")
    ap.add_argument("--template-bin", help="分页请求模板的二进制文件")

    # 仅替换日期/代码/可选市场
    ap.add_argument("--date", required=True, help="YYYYMMDD，8位")
    ap.add_argument("--code", required=True, help="6位股票代码")

    # offset 字段配置
    ap.add_argument("--offset-pos", default="0x0C,0x10",
                    help="请求里两个 offset 字段的起始位置（字节，十进制或0x），如 0x0C,0x10；如只有一个字段可写成 0x10,0x10")
    ap.add_argument("--offset-write", choices=["both-same", "field2-only", "base-plus-step"], default="field2-only",
                    help="写 offset 的方式，默认仅写第二个（与你首包一致）")
    ap.add_argument("--start-offset", type=lambda s: int(s, 0),
                    help="首轮使用的 offset（默认读取模板 pos2 对应的值）")
    ap.add_argument("--step", type=lambda s: int(s, 0), default=0x7530,
                    help="每页递增步长，默认 0x7530=30000")

    # 接收/停止策略
    ap.add_argument("--send-hello", action="store_true",
                    help="连接后先发送一次 HELLO 请求（使用内置/指定的 hello 载荷）")
    ap.add_argument("--pre-wait-ms", type=int, default=0,
                    help="连接后先等待接收静默（毫秒），用于收欢迎数据；默认 0（不等待）")
    ap.add_argument("--recv-quiet-ms", type=int, default=1200,
                    help="每轮接收静默阈值（毫秒），聚合分片直到静默")
    ap.add_argument("--final-wait-ms", type=int, default=1500,
                    help="最后一轮结束后再等尾包（毫秒）")
    ap.add_argument("--max-pages", type=int, default=999,
                    help="最多分页数（防止无限循环）")
    ap.add_argument("--baseline-bytes", type=int,
                    help="标准页参考字节数（接收端统计）；未提供则以第1页实际收到字节数为基线")
    ap.add_argument("--stop-ratio", type=float, default=0.6,
                    help="短页停阈值：若本页字节数 < baseline * ratio，则视为末页并停止")
    ap.add_argument("--min-drop", type=int, default=4096,
                    help="短页停的最小绝对差：同时要求本页 <= baseline - min_drop 更稳妥")

    # 输出
    ap.add_argument("--out-dir", default="tcp_paged_out", help="输出目录")
    ap.add_argument("--save-hello-recv", action="store_true", help="保存 HELLO 后收到的数据（若有）")
    ap.add_argument("--verbose", action="store_true", help="打印更多调试信息")

    args = ap.parse_args()

    hello_payload = load_payload_from_args(args.hello_hex, args.hello_bin, DEFAULT_HELLO_HEXDUMP)
    hello_payload = replace_date_code(hello_payload, args.date, args.code)

    tpl = load_payload_from_args(args.template_hex, args.template_bin, DEFAULT_REQ_HEXDUMP)
    tpl = replace_date_code(tpl, args.date, args.code)

    # 解析 offset 位置
    a, b = args.offset_pos.split(",")
    pos1 = int(a, 0)
    pos2 = int(b, 0)

    # 决定起始 offset
    tpl_off2 = read_offset_le(tpl, pos2)
    cur_off = args.start_offset if args.start_offset is not None else tpl_off2

    out_dir = Path(args.out_dir).resolve()
    (out_dir / "messages").mkdir(parents=True, exist_ok=True)

    meta = {
        "host": args.host,
        "port": args.port,
        "start_utc": utc_now_iso(),
        "date": args.date,
        "code": args.code,
        "offset_positions": [pos1, pos2],
        "offset_write": args.offset_write,
        "start_offset": cur_off,
        "step": args.step,
        "recv_quiet_ms": args.recv_quiet_ms,
        "final_wait_ms": args.final_wait_ms,
        "pages": [],
        "bytes_received_total": 0,
    }

    print(f"[info] 连接 {args.host}:{args.port}（proxy={args.socks5 or 'none'}），offset pos={pos1},{pos2} 模式={args.offset_write}")
    with connect(args.host, args.port, args.socks5, timeout=10.0) as sock:
        # 连接后可选预接收（欢迎数据）
        if args.pre_wait_ms > 0:
            pre = recv_until_quiet(sock, args.pre_wait_ms)
            if pre:
                (out_dir / "welcome_recv.bin").write_bytes(pre)
                meta["bytes_received_total"] += len(pre)
                print(f"[recv] 连接后欢迎数据 {len(pre)} bytes")

        # 可选发送 HELLO 请求
        if args.send_hello:
            sock.sendall(hello_payload)
            print(f"[send] HELLO {len(hello_payload)} bytes")
            hello_resp = recv_until_quiet(sock, args.recv_quiet_ms)
            if hello_resp:
                meta["bytes_received_total"] += len(hello_resp)
                if args.save_hello_recv:
                    (out_dir / "hello_resp.bin").write_bytes(hello_resp)
                print(f"[recv] HELLO 响应 {len(hello_resp)} bytes")

        # 分页循环（短页停）
        baseline = args.baseline_bytes
        for i in range(args.max_pages):
            req = write_offset_le(tpl, pos1, args.step*i)
            # print(hexdump(req))
            sock.sendall(req)
            if args.verbose:
                print(f"[send] page={i} off={cur_off} bytes={len(req)}")

            resp = recv_until_quiet(sock, args.recv_quiet_ms)
            got = len(resp)

            # 0 字节直接结束
            if got == 0:
                print(f"[stop] 收到 0 字节，结束。")
                break

            meta["bytes_received_total"] += got
            page_name = f"msg_s2c_{i:04d}.bin"
            (out_dir / "messages" / page_name).write_bytes(resp)
            meta["pages"].append({
                "index": i,
                "offset": cur_off,
                "bytes_received": got,
                "timestamp": utc_now_iso(),
                "filename": f"messages/{page_name}",
            })

            # 建立基线（首个标准页）
            if baseline is None:
                baseline = got
                print(f"[info] baseline（标准页字节数）={baseline}")

            print(f"[recv] page={i} bytes={got}")

            # 短页停判定：显著短于基线
            threshold = int(max(baseline * args.stop_ratio, baseline - args.min_drop))
            if got < threshold:
                print(f"[stop] 短页停：本页 {got} < 阈值 {threshold}（baseline={baseline}, ratio={args.stop_ratio}, min_drop={args.min_drop}）")
                break

            # 下一页 offset
            cur_off += args.step

        # 尾部等待
        if args.final_wait_ms > 0:
            tail = recv_until_quiet(sock, args.final_wait_ms)
            if tail:
                (out_dir / "tail.bin").write_bytes(tail)
                meta["bytes_received_total"] += len(tail)
                print(f"[recv] 尾部追加 {len(tail)} bytes")

    meta["end_utc"] = utc_now_iso()
    (out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[done] 收到总字节：{meta['bytes_received_total']}，输出目录：{out_dir}")
    print("[hint] 若出现过早/过晚停止，可调整 --stop-ratio 或 --min-drop；如 offset 两字段关系不同，切换 --offset-write。")
if __name__ == "__main__":
    main()