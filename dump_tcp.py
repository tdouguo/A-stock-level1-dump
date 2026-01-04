from mitmproxy import ctx
from datetime import datetime
from pathlib import Path
import json, re, os

def safe(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z\.\-:_]", "_", s)

class TcpDumpAddon:
    def __init__(self):
        base = os.environ.get("MITM_CAP_DIR", "./captures2")
        self.base = Path(base).expanduser().resolve()
        self.base.mkdir(parents=True, exist_ok=True)
        ctx.log.info(f"[dump] saving to: {self.base}")

    def tcp_start(self, flow):
        sc = flow.server_conn
        host, port = (sc.address[0], sc.address[1]) if sc.address else ("unknown", 0)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        dpath = self.base / f"{ts}_{safe(host)}_{port}"
        dpath.mkdir(parents=True, exist_ok=True)
        
        # 创建消息序列目录
        messages_dir = dpath / "messages"
        messages_dir.mkdir(exist_ok=True)
        
        flow.metadata.update({
            "dump_dir": dpath,
            "messages_dir": messages_dir,
            "c2s_path": dpath / "c2s.bin",  # 保留原有的合并文件
            "s2c_path": dpath / "s2c.bin",  # 保留原有的合并文件
            "bytes_c2s": 0, "bytes_s2c": 0,
            "message_count": 0,
            "c2s_count": 0,
            "s2c_count": 0,
            "start_ts": datetime.utcnow().isoformat() + "Z",
        })
        meta = {
            "dst_host": host, "dst_port": port,
            "start_utc": flow.metadata["start_ts"],
            "mitmproxy_client_conn": {
                "address": getattr(flow.client_conn, "address", None),
                "sni": getattr(sc, "sni", None),
            },
        }
        (dpath / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        ctx.log.info(f"[tcp_start] {host}:{port} -> {dpath}")

    def tcp_message(self, flow):
        msg = flow.messages[-1]
        timestamp = datetime.utcnow()
        
        # 获取消息计数器
        flow.metadata["message_count"] += 1
        msg_id = flow.metadata["message_count"]
        
        if msg.from_client:
            # 客户端到服务器的数据
            flow.metadata["c2s_count"] += 1
            c2s_id = flow.metadata["c2s_count"]
            
            # 创建单独的消息文件
            msg_filename = f"msg_{msg_id:04d}_c2s_{c2s_id:04d}.bin"
            msg_path = flow.metadata["messages_dir"] / msg_filename
            msg_path.write_bytes(msg.content)
            
            # 同时写入合并文件（保持向后兼容）
            with open(flow.metadata["c2s_path"], "ab") as f: 
                f.write(msg.content)
            flow.metadata["bytes_c2s"] += len(msg.content)
    
            msg_meta = {
                "message_id": msg_id,
                "direction": "client_to_server",
                "sequence": c2s_id,
                "timestamp": timestamp.isoformat() + "Z",
                "size": len(msg.content),
                "filename": msg_filename
            }
        else:
            # 服务器到客户端的数据
            flow.metadata["s2c_count"] += 1
            s2c_id = flow.metadata["s2c_count"]
            
            # 创建单独的消息文件
            msg_filename = f"msg_{msg_id:04d}_s2c_{s2c_id:04d}.bin"
            msg_path = flow.metadata["messages_dir"] / msg_filename
            msg_path.write_bytes(msg.content)
            
            # 同时写入合并文件（保持向后兼容）
            with open(flow.metadata["s2c_path"], "ab") as f: 
                f.write(msg.content)
            flow.metadata["bytes_s2c"] += len(msg.content)
            
            # 记录消息元数据
            msg_meta = {
                "message_id": msg_id,
                "direction": "server_to_client", 
                "sequence": s2c_id,
                "timestamp": timestamp.isoformat() + "Z",
                "size": len(msg.content),
                "filename": msg_filename
            }
        
        # 保存消息元数据到单独的json文件
        meta_filename = f"msg_{msg_id:04d}_meta.json"
        meta_path = flow.metadata["messages_dir"] / meta_filename
        meta_path.write_text(json.dumps(msg_meta, ensure_ascii=False, indent=2), encoding="utf-8")

    def tcp_end(self, flow):
        dpath = flow.metadata.get("dump_dir")
        if not dpath: return
        meta_path = dpath / "meta.json"
        try: meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception: meta = {}
        meta.update({
            "end_utc": datetime.utcnow().isoformat() + "Z",
            "bytes_c2s": flow.metadata.get("bytes_c2s", 0),
            "bytes_s2c": flow.metadata.get("bytes_s2c", 0),
            "total_messages": flow.metadata.get("message_count", 0),
            "c2s_messages": flow.metadata.get("c2s_count", 0),
            "s2c_messages": flow.metadata.get("s2c_count", 0),
        })
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        ctx.log.info(f"[tcp_end] saved {dpath} c2s={meta['bytes_c2s']} s2c={meta['bytes_s2c']} msgs={meta['total_messages']}")

addons = [TcpDumpAddon()]