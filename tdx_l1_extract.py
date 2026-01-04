import sys, os, re, json, struct, zlib
from pathlib import Path
from typing import List, Tuple, Optional

MAGIC = b"\xb1\xcb\x74\x00"  # 0x0074CBB1
ZLIB_HEADS = {b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}

def find_all(hay: bytes, needle: bytes) -> List[int]:
    offs, i = [], 0
    while True:
        j = hay.find(needle, i)
        if j < 0: break
        offs.append(j); i = j + 1
    return offs

def slice_blocks(stream: bytes) -> List[bytes]:
    idx = find_all(stream, MAGIC)
    if not idx: return []
    blocks = []
    for i, off in enumerate(idx):
        end = idx[i+1] if i+1 < len(idx) else len(stream)
        blocks.append(stream[off:end])
    return blocks

def find_ascii_hex32(buf: bytes) -> Optional[str]:
    m = re.search(rb"[\x00-\x01]([0-9a-f]{32})\x00", buf)
    return m.group(1).decode() if m else None

def peek_u16_u32_le(buf: bytes, count: int = 8):
    u16s, u32s = [], []
    for i in range(0, min(len(buf), count*2), 2):
        u16s.append(int.from_bytes(buf[i:i+2], "little"))
    for i in range(0, min(len(buf), count*4), 4):
        u32s.append(int.from_bytes(buf[i:i+4], "little"))
    return u16s, u32s

def read_u32le(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+4], "little")

def guess_len_pair(b: bytes, zi: int, total_len: int) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """
    在 zlib 头前 8 或 12 字节内猜测 [comp_len][uncomp_len] 或 [uncomp_len][comp_len]
    返回: (comp_len, uncomp_len, len_pos)
    """
    comp_len = uncomp_len = pos = None
    for back in (8, 12):
        if zi >= back:
            a = read_u32le(b, zi - back)
            c = read_u32le(b, zi - back + 4)
            # 方案1: [comp][uncomp]
            if 8 <= a <= (total_len - zi) and 16 <= c <= 100_000_000 and a < c:
                comp_len, uncomp_len, pos = a, c, zi - back
                break
            # 方案2: [uncomp][comp]
            if 8 <= c <= (total_len - zi) and 16 <= a <= 100_000_000 and c < a:
                comp_len, uncomp_len, pos = c, a, zi - back
                break
    return comp_len, uncomp_len, pos

def decompress_exact(zbuf: bytes) -> Tuple[bytes, int]:
    d = zlib.decompressobj(15)
    out = d.decompress(zbuf)
    used = len(zbuf) - len(d.unused_data)
    return out, used

def scan_zlib_segments(block: bytes, search_start: int = 0):
    """
    在一个块内找到一个或多个 zlib 段。
    产出: (zlib_offset, comp_len, uncomp_len, out_bytes, used_bytes)
    """
    i = search_start
    end = len(block)
    while i < end - 2:
        # 找 zlib 头
        found = None
        for j in range(i, end - 1):
            if block[j:j+2] in ZLIB_HEADS:
                found = j; break
        if found is None:
            return
        zi = found
        comp_len, uncomp_len, lp = guess_len_pair(block, zi, end)
        try:
            if comp_len is not None:
                zslice = block[zi: zi + comp_len]
                out, used = decompress_exact(zslice)
                # 容错：如果 used < comp_len，说明 comp_len 可能偏大，按 used 截断
                comp_used = used if used > 0 else comp_len
            else:
                # 无长度字段，解到 unused_data 为止
                out, used = decompress_exact(block[zi:])
                comp_used = used if used > 0 else (len(block) - zi)
            yield (zi, comp_len or comp_used, uncomp_len, out, comp_used)
            i = zi + comp_used
        except Exception:
            # 解失败，跳过这个 zlib 头，从下一字节继续扫
            i = zi + 1
            continue



def merge_zlib_segments(path: Path):
    """message文件夹下的s2c_xxxx.bin是分片传输的，现在需要将他们合并成一个完整的s2c.bin文件
    合并的逻辑如下：msg_s2c_0001.bin 没有什么内容可以忽略
    msg_s2c_0002.bin 是真正数据开头
    msg_s2c_0003.bin 以及后面的 msg_s2c_004.bin 等后面的数据
     的数据开头有一个公共头，需要检测这个公共头，然后将公共头删除，再追加到msg_s2c_0002.bin后面
    """
    if not path.is_dir():
        print(f"[!] {path} 不是目录")
        return
    
    # 查找所有 s2c 分片文件
    s2c_files = []
    for file in path.glob("msg_s2c_*.bin"):
        s2c_files.append(file)
    
    if not s2c_files:
        print(f"[!] 在 {path} 中未找到 s2c 分片文件")
        return
    
    # 按文件名排序
    s2c_files.sort()    
    base_file = None
    append_files = []
    
    for file in s2c_files:
        if "_s2c_0000.bin" in file.name:
            base_file = file
        else:
            append_files.append(file)
    if not base_file:
        print("[!] 未找到基础文件 (*_s2c_0000.bin)")
        return
    
    # 读取基础文件内容
    merged_data = base_file.read_bytes()
    
    
    # 合并文件
    for append_file in append_files:
        data = append_file.read_bytes()
        # 打印出前20字节，以16进制形式显示
        print(f"[*] {append_file.name}: 前20字节 {data[:12].hex()}")
        # 判断该片段是否为分片数据
        if data.startswith(MAGIC):
            # 如果是分片数据，去掉前20字节
            print(f"[+] {append_file.name} 是分片数据，去掉前20字节")
            merged_data += data[20:]
        else:
            merged_data += data

    # 生成合并后的文件
    output_file = path / "s2c.bin"
    output_file.write_bytes(merged_data)
    print(f"[+] 合并完成: {output_file}, 总大小: {len(merged_data)} 字节")

def process(target: Path):
    merge_zlib_segments(target)

    if target.is_file():
        raw = target.read_bytes()
        base_dir = target.parent
    else:
        s2c = target / "s2c.bin"
        if not s2c.exists():
            print(f"[!] {target} 不存在 s2c.bin"); return
        raw = s2c.read_bytes()
        base_dir = target

    out_magic = base_dir / "out_magic"
    out_magic.mkdir(exist_ok=True)
    blocks = slice_blocks(raw)
    if not blocks:
        print("[!] 未找到 MAGIC 0x0074CBB1"); return
    print(f"[*] 找到 {len(blocks)} 个块（以 MAGIC 分割）")

    for i, blk in enumerate(blocks):
        bdir = out_magic / f"block_{i:06d}"
        bdir.mkdir(parents=True, exist_ok=True)
        (bdir / "block.bin").write_bytes(blk)

        # 头部与元信息
        # 在前 512 字节内搜第一个 zlib 头；若没有，再全块搜。
        first_zi = None
        for lim in (512, len(blk)):
            for j in range(0, lim-1):
                if blk[j:j+2] in ZLIB_HEADS:
                    first_zi = j; break
            if first_zi is not None: break
        header = blk[: first_zi if first_zi is not None else min(256, len(blk))]
        (bdir / "header.bin").write_bytes(header)
        u16s, u32s = peek_u16_u32_le(header, 16)
        meta = {
            "magic_ok": blk[:4] == MAGIC,
            "block_len": len(blk),
            "zlib_first_offset": first_zi,
            "ascii_hex32": find_ascii_hex32(blk),
            "peek_u16_le": u16s, "peek_u32_le": u32s,
        }

        # 扫描多段 zlib
        seg_idx = 0
        for (zi, comp_len, uncomp_len, out, used) in scan_zlib_segments(blk, 0):
            # 保存压缩与解压段
            zslice = blk[zi: zi + comp_len]
            (bdir / f"payload_{seg_idx:03d}.z.bin").write_bytes(zslice)
            (bdir / f"payload_{seg_idx:03d}.bin").write_bytes(out)
            meta.setdefault("segments", []).append({
                "zlib_offset": zi,
                "comp_len": comp_len,
                "uncomp_len_claim": uncomp_len,
                "used_bytes": used,
                "out_len": len(out),
            })
            seg_idx += 1

        (bdir / "header.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] block_{i:06d}: {len(meta.get('segments', []))} 段 zlib 已解出")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python tdx_l2_extract_v3.py <会话目录 | s2c.bin 路径>")
        sys.exit(2)
    process(Path(sys.argv[1]))

    # merge_zlib_segments(Path("F:/tdx_dump/captures2/20250810_021656_123_120.237.21.226_7709/messages/"))