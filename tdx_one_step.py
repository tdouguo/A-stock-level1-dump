#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一体化通达信数据提取脚本
- 自动执行数据获取、提取和解析为CSV的完整流程
- 简化参数：只需提供日期、股票代码和输出目录
- 自动处理中间文件路径
- CSV文件以日期和代码命名
"""

import argparse
import os
import sys
import tempfile
import shutil
from pathlib import Path
import time

# 导入三个脚本的核心功能
from tcp_send import (
    connect, recv_until_quiet, parse_hexdump, load_payload_from_args,
    replace_date_code, read_offset_le, write_offset_le, utc_now_iso,
    DEFAULT_HELLO_HEXDUMP, DEFAULT_REQ_HEXDUMP
)
from tdx_l1_extract import process as extract_process
from tdx_l1_parse import extract_csv

def main():
    # 简化的参数解析
    parser = argparse.ArgumentParser(description="一体化通达信数据提取工具")
    parser.add_argument("--date", required=True, help="日期，格式为YYYYMMDD")
    parser.add_argument("--code", required=True, help="股票代码，6位数字")
    parser.add_argument("--host", default="120.237.21.226", help="服务器地址，默认为120.237.21.226")
    parser.add_argument("--port", type=int, default=7709, help="服务器端口，默认为7709")
    parser.add_argument("--output-dir", default="./output", help="CSV输出目录，默认为./output")
    parser.add_argument("--keep-temp", action="store_true", help="保留中间临时文件")
    args = parser.parse_args()

    # 创建临时目录和输出目录
    temp_dir = Path(tempfile.mkdtemp(prefix=f"tdx_temp_{args.date}_{args.code}_"))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # CSV文件名
    csv_filename = f"{args.date}_{args.code}.csv"
    csv_path = output_dir / csv_filename

    try:
        print(f"[1/3] 正在获取数据: 日期={args.date}, 代码={args.code}...")
        
        # 步骤1: 执行TCP数据获取 (tcp_send.py的主要功能)
        data_dir = temp_dir / f"out_{args.date}_{args.code}"
        (data_dir / "messages").mkdir(parents=True, exist_ok=True)
        
        # 加载载荷并替换日期和代码
        hello_payload = load_payload_from_args(None, None, DEFAULT_HELLO_HEXDUMP)
        hello_payload = replace_date_code(hello_payload, args.date, args.code)
        
        tpl = load_payload_from_args(None, None, DEFAULT_REQ_HEXDUMP)
        tpl = replace_date_code(tpl, args.date, args.code)

        # 解析offset位置
        pos1, pos2 = 0x0C, 0x10
        tpl_off2 = read_offset_le(tpl, pos2)
        cur_off = tpl_off2
        step = 0x7530  # 默认步长
        
        # 连接并发送请求
        with connect(args.host, args.port, None, timeout=10.0) as sock:
            # 发送HELLO请求
            sock.sendall(hello_payload)
            hello_resp = recv_until_quiet(sock, 1200)
            
            # 分页循环获取数据
            baseline = None
            for i in range(4):  # 最多4页
                req = write_offset_le(tpl, pos1, step*i)
                sock.sendall(req)
                
                resp = recv_until_quiet(sock, 1200)
                got = len(resp)
                
                if got == 0:
                    break
                
                page_name = f"msg_s2c_{i:04d}.bin"
                (data_dir / "messages" / page_name).write_bytes(resp)
                
                if baseline is None:
                    baseline = got
                
                # 短页停判定
                threshold = int(max(baseline * 0.6, baseline - 4096))
                if got < threshold:
                    break
                
                cur_off += step
            
            # 最终等待
            tail = recv_until_quiet(sock, 1500)
        
        print(f"[2/3] 正在提取数据...")
        # 步骤2: 执行数据提取 (tdx_l1_extract.py的主要功能)
        extract_process(data_dir / "messages")
        
        print(f"[3/3] 正在解析数据并生成CSV...")
        # 步骤3: 执行数据解析并生成CSV (tdx_l1_parse.py的主要功能)
        magic_dir = data_dir / "messages" / "out_magic"
        payload_path = magic_dir / "block_000000" / "payload_000.bin"
        if not payload_path.exists():
            print(f"错误: 未找到Payload文件: {payload_path}")
            sys.exit(1)
        
        # 解析为CSV
        extract_csv(payload_path, csv_path)
        
        print(f"处理完成! CSV文件已保存到: {csv_path}")
        
    except Exception as e:
        print(f"错误: {str(e)}")
        raise
    finally:
        # 清理临时文件
        if not args.keep_temp:
            shutil.rmtree(temp_dir, ignore_errors=True)
            print(f"临时文件已清理")
        else:
            print(f"临时文件保留在: {temp_dir}")

if __name__ == "__main__":
    # 计算main函数耗时
    start_time = time.perf_counter()
    main()
    end_time = time.perf_counter()
    duration = end_time - start_time
    print(f"main函数耗时: {duration:.4f}秒") # 大概耗时10s
