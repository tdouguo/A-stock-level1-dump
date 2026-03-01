#!/bin/bash
# 批量下载指定日期范围内的股票数据（自动跳过非交易日）

START_DATE="20240401"
END_DATE="20250401"
CONCURRENT=100

# 将 YYYYMMDD 转为秒（macOS 兼容）
to_epoch() {
    local d=$1
    date -j -f "%Y%m%d" "$d" "+%s"
}

# 将秒转回 YYYYMMDD
from_epoch() {
    date -j -f "%s" "$1" "+%Y%m%d"
}

current=$(to_epoch "$START_DATE")
end=$(to_epoch "$END_DATE")

while [ "$current" -le "$end" ]; do
    date_str=$(from_epoch "$current")

    echo "=============================="
    echo "▶ 处理日期: $date_str"
    echo "=============================="

    ./target/release/bulk_download "$date_str" "$CONCURRENT"
    exit_code=$?

    if [ $exit_code -eq 1 ]; then
        echo "⏭  $date_str 非交易日，跳过"
    elif [ $exit_code -ne 0 ]; then
        echo "❌ $date_str 下载失败 (exit=$exit_code)，继续下一天"
    fi

    # 前进一天（86400 秒）
    current=$((current + 86400))
done

echo ""
echo "✅ 全部日期处理完毕 ($START_DATE ~ $END_DATE)"
