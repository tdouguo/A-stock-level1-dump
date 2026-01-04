#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pdb
import sys
import pandas as pd
from pathlib import Path
from typing import List

STX = 0x02  # 字段分隔
ETX = 0x03  # 记录起始
EOT = 0x04  # 帧分隔

def iter_frames(buf: bytes):
    """以 ... [EOT,ETX] ... 作为帧边界切分；首尾残段也返回。"""
    i = 0
    n = len(buf)
    while i < n:
        j = buf.find(bytes([EOT, ETX]), i)
        if j == -1:
            yield buf[i:n]
            break
        yield buf[i:j]
        i = j + 2

def tokenize(rec: bytes) -> List[bytes]:
    """去掉前导 ETX，按 STX 切分，剔除空 token。"""
    if rec and rec[0] == ETX:
        rec = rec[1:]
    if not rec:
        return []
    parts = rec.split(bytes([STX]))
    return [p for p in parts if p]

def b2s(b: bytes) -> str:
    return b.decode("latin-1").strip()

def extract_csv(file, output):
    infile = Path(file)
    if infile.exists():
        buf = infile.read_bytes()
    frames = list(iter_frames(buf))
    #04 未知
    # 05 开盘价格
    #08 成交价格
    #100.00 成交手数
    #1A0.0000 成交金额
    #09 分笔数量
    #涨停价格"1E10.510000",
    # 跌停价格1F8.600000",
    # 1C 市盈率"1C110.660000",

    column_name = [
        "代码", "时间", "卖出平均价格", "累计成交量", "累计成交金额", "累计笔数", "最高价", "最低价",
        "卖5价", "卖5量", "卖4价", "卖4量", "卖3价", "卖3量", "卖2价", "卖2量", "卖1价", "卖1量",
        "买1价", "买1量", "买2价", "买2量", "买3价", "买3量", "买4价", "买4量", "买5价", "买5量"
    ]

    column = [
        "01", "0T", "08", "10", "1A","09", "06", "07",
        "44", "54",
        "43", "53",
        "42", "52",
        "41", "51",
        "40", "50",
        "20", "30",
        "21", "31",
        "22", "32",
        "23", "33",
        "24", "34",
    ]

    df = pd.DataFrame(columns=column)
    for i, frame in enumerate(frames):
        if not frame:
            continue
        tokens_b = tokenize(frame)
        tokens_s = [b2s(t) for t in tokens_b]
        if i == 0 or i == 1:
            continue
        else:
            if df is None or (df.empty and len(df.columns) == 0):
                df = pd.DataFrame(columns=column)
                continue
            new_row = {}
            token_dict = {}
            for token in tokens_s:
                if len(token) >= 2:
                    prefix = token[:2]
                    token_dict[prefix] = token[2:]
            for col in df.columns:
                col_prefix = col[:2]
                if col_prefix in token_dict:
                    new_row[col] = token_dict[col_prefix]
                else:
                    if len(df) > 0:
                        new_row[col] = df.iloc[-1][col]
                    else:
                        new_row[col] = None
            df.loc[len(df)] = new_row
    df.columns = column_name
    df.to_csv(output, index=False, encoding="utf-8-sig")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python tdx_l1_parse.py payload.bin <输出CSV路径>")
        sys.exit(2)
    extract_csv(sys.argv[1], sys.argv[2])