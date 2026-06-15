// ======  Proxy Controller (Active-Standby Multi-Tunnel) ======

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;

    // --- 提取并处理云端安全隔离变量 ---
    const WEB_USER = env.WEB_USER || "admin";        
    const WEB_PASS = env.WEB_PASS || "admin888";     
    const PROXY_USER = env.PROXY_USER || "proxy";    
    const PROXY_PASS = env.PROXY_PASS || "888888";   

    const authenticate = (request) => {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(" ");
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const [username, password] = decoded.split(":");
        return username === WEB_USER && password === WEB_PASS;
      } catch (e) {
        return false;
      }
    };

    const unauthorizedResponse = () => {
      return new Response("Unauthorized Access. Scanner Blocked.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Proxy System Security Control"',
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    };

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS servers (
        ip TEXT PRIMARY KEY,
        details TEXT,
        last_seen INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS server_logs (
        ip TEXT PRIMARY KEY,
        logs TEXT,
        updated_at INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS global_config (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `).run();

    if (url.pathname === "/scripts/proxy_server.py") {
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64
from typing import Any

PROXY_USER = b"${PROXY_USER}"
PROXY_PASS = b"${PROXY_PASS}"

# 全局软开关字典：{listen_port: tun_interface_name}，由 lite_manager 动态更新
ACTIVE_BINDS = {}

def parse_int(value: Any) -> int:
    try: return int(value)
    except: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def create_connection(address: tuple[str, int], timeout: float = 20, listen_port: int = 0) -> socket.socket:
    bind_interface = ACTIVE_BINDS.get(listen_port, "")
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored: return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data: return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes, listen_port: int = 0) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        
        if b"\\x02" not in methods:
            client.sendall(b"\\x05\\xFF") 
            return
        client.sendall(b"\\x05\\x02")
        
        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)
        
        if uname != PROXY_USER or upass != PROXY_PASS:
            client.sendall(b"\\x01\\x01") 
            return
        client.sendall(b"\\x01\\x00") 

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")
        
        upstream = create_connection((host, port), timeout=20, listen_port=listen_port)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes, listen_port: int = 0) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\\r\\n\\r\\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\\r\\n")
        
        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if line.split(":", 1)[1].strip() == expected_auth:
                    auth_passed = True
                    break
                    
        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\nProxy-Authenticate: Basic realm=\\"Proxy\\"\\r\\n\\r\\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), timeout=20, listen_port=listen_port)
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\\r\\n" + "\\r\\n".join(headers) + "\\r\\nConnection: close\\r\\n\\r\\n"
        upstream = create_connection((parsed.hostname, port), timeout=20, listen_port=listen_port)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int], listen_port: int = 0) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first, listen_port)
        else: http_client(client, first, listen_port)
    except:
        try: client.close()
        except: pass

def start_proxy_server(host: str, ports: list) -> None:
    if isinstance(ports, int): ports = [ports]
    servers = {}
    for p in ports:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, p))
            srv.listen(256)
            servers[p] = srv
        except Exception as e:
            print(f"[-] 端口 {p} 绑定失败: {e}")
    if not servers: return
    all_socks = list(servers.values())
    while True:
        readable, _, _ = select.select(all_socks, [], [], 1)
        for srv in readable:
            port = next(p for p, s in servers.items() if s is srv)
            try:
                client, address = srv.accept()
                threading.Thread(target=proxy_client, args=(client, address, port), daemon=True).start()
            except: time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/scripts/lite_manager.py") {
      const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, subprocess, threading, time, urllib.request, json
from pathlib import Path
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = "${domain}"

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"

WEB_USER = "${WEB_USER}"
WEB_PASS = "${WEB_PASS}"

PROXY_PORT = 7920

state_lock = threading.Lock()
dead_ips = set()
last_blacklist_clear = time.time()
public_ip = ""

global_node_reservoir = {} 
reservoir_lock = threading.Lock()

class Tunnel:
    def __init__(self, name: str, table_id: int):
        self.name = name
        self.table_id = table_id
        self.process = None
        self.node = None
        self.entry_ip = ""
        self.egress_ip = ""
        self.country = ""
        self.ready = False
        self.connected_at = 0
        self.is_connecting = False

class Region:
    def __init__(self, idx: int, country: str, port: int):
        self.idx = idx
        self.country = country
        self.port = port
        self.switch_trigger = 0
        base_table = 200 + idx * 100
        self.main = Tunnel(f"tun_r{idx}m", base_table)
        self.backup = Tunnel(f"tun_r{idx}b", base_table + 1)

regions = {}
regions_lock = threading.Lock()

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except: public_ip = "Unknown_IP"

def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Authorization": f"Basic {auth_ptr}"
    }

def get_recent_logs():
    try:
        res = subprocess.run(["journalctl", "-u", "proxy-lite.service", "-n", "30", "--no-pager", "--output=cat"], capture_output=True, text=True, errors="replace")
        return res.stdout
    except: return "Waiting for logs..."

def _force_switch_region(reg):
    active_name = proxy_server.ACTIVE_BINDS.get(reg.port, reg.main.name)
    if active_name == reg.main.name:
        active_tun, standby_tun = reg.main, reg.backup
    else:
        active_tun, standby_tun = reg.backup, reg.main
    print(f"[*] 地区 [{reg.idx}] 强制更换 IP，仅清退活跃通道...", flush=True)
    with state_lock:
        if active_tun.entry_ip: dead_ips.add(active_tun.entry_ip)
        if active_tun.process:
            try: active_tun.process.terminate(); active_tun.process.wait(2)
            except: active_tun.process.kill()
        active_tun.ready = False; active_tun.process = None
        active_tun.entry_ip = ""; active_tun.egress_ip = ""
        if standby_tun.ready and standby_tun.process and standby_tun.process.poll() is None:
            proxy_server.ACTIVE_BINDS[reg.port] = standby_tun.name
            print(f"[*] 地区 [{reg.idx}] 软开关秒切至备用: {standby_tun.egress_ip or standby_tun.entry_ip}", flush=True)
        else:
            proxy_server.ACTIVE_BINDS.pop(reg.port, None)
            print(f"[*] 地区 [{reg.idx}] 备用通道也不可用，清除绑定，等待重拨...", flush=True)

def _kill_region_tunnels(reg):
    with state_lock:
        for tun in [reg.main, reg.backup]:
            if tun.entry_ip: dead_ips.add(tun.entry_ip)
            if tun.process:
                try: tun.process.terminate(); tun.process.wait(2)
                except: tun.process.kill()
            tun.ready = False; tun.process = None; tun.entry_ip = ""; tun.egress_ip = ""
    proxy_server.ACTIVE_BINDS.pop(reg.port, None)

def teardown_region(reg):
    print(f"[*] 移除地区 [{reg.idx}]: {reg.country}", flush=True)
    for tun in [reg.main, reg.backup]:
        if tun.process:
            try: tun.process.terminate(); tun.process.wait(2)
            except: tun.process.kill()
        subprocess.run(["ip", "rule", "del", "pref", str(tun.table_id)], capture_output=True)
        subprocess.run(["ip", "rule", "del", "pref", str(tun.table_id + 1000)], capture_output=True)
        subprocess.run(["ip", "route", "flush", "table", str(tun.table_id)], capture_output=True)
    proxy_server.ACTIVE_BINDS.pop(reg.port, None)

def reconcile_regions(desired):
    global regions, PROXY_PORT
    with regions_lock:
        desired_idxs = {int(r["idx"]) for r in desired}
        for idx in list(regions.keys()):
            if idx not in desired_idxs:
                teardown_region(regions[idx])
                del regions[idx]
        for rdata in desired:
            idx = int(rdata["idx"])
            country = str(rdata["country"]).upper()
            port = int(rdata.get("port", 7920 + idx))
            switch_trigger = int(rdata.get("switch_trigger", 0))
            if idx not in regions:
                reg = Region(idx, country, port)
                regions[idx] = reg
                print(f"[*] 新增地区 [{idx}]: {country} 端口 {port}", flush=True)
            else:
                reg = regions[idx]
                if reg.country != country:
                    print(f"[*] 地区 [{idx}] 国家变更: {reg.country} -> {country}", flush=True)
                    _kill_region_tunnels(reg)
                    reg.country = country
                if port != reg.port:
                    print(f"[*] 地区 [{idx}] 端口变更 {reg.port} -> {port}，重启...", flush=True)
                    os._exit(0)
            if switch_trigger > reg.switch_trigger:
                reg.switch_trigger = switch_trigger
                _force_switch_region(reg)

def update_config_loop():
    global PROXY_PORT
    while True:
        try:
            req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
            with urllib.request.urlopen(req, timeout=10) as res:
                data = json.loads(res.read().decode("utf-8"))
                desired_regions = data.get("regions", [])
                if not desired_regions:
                    desired_regions = [{"idx": 0, "country": data.get("0", "JP"), "port": int(data.get("port", 7920))}]
                reconcile_regions(desired_regions)
        except Exception as e: pass
        time.sleep(15)

def c2_heartbeat_loop():
    global public_ip
    while True:
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with regions_lock:
            for reg in regions.values():
                with state_lock:
                    for tun in [reg.main, reg.backup]:
                        if tun.ready and tun.process and tun.process.poll() is None:
                            uptime = time.time() - tun.connected_at
                            details.append({
                                "tunnel": tun.name,
                                "region_idx": reg.idx,
                                "active": proxy_server.ACTIVE_BINDS.get(reg.port) == tun.name,
                                "country": reg.country,
                                "port": reg.port,
                                "connected_time": int(uptime),
                                "node_ip": tun.egress_ip if tun.egress_ip else tun.entry_ip
                            })
        
        payload = json.dumps({"ip": public_ip, "details": details, "logs": get_recent_logs()}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
        except Exception as e: pass
        time.sleep(8)

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n", encoding="utf-8")
        AUTH_FILE.chmod(0o600)
    # 强制系统解除反向路径过滤，防止策略路由双拨时数据包被内核丢弃
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"], capture_output=True)

def harvest_snapshot_nodes() -> list:
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip, 
                "ping": int(raw_ping) if raw_ping.isdigit() else 9999, 
                "country": row.get("CountryShort", "").upper(), 
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        return nodes
    except Exception as e: return []

def vpngate_fetch_loop():
    global global_node_reservoir, dead_ips
    while True:
        snapshot = harvest_snapshot_nodes()
        if snapshot:
            with reservoir_lock:
                for n in snapshot:
                    if n["ip"] not in dead_ips:
                        global_node_reservoir[n["ip"]] = n
            print(f"[*] ⚡ 节点库更新，当前囤积有效节点 -> {len(global_node_reservoir)} 个", flush=True)
        time.sleep(300)

def setup_routing(tun_name: str, table_id: int):
    subprocess.run(["ip", "rule", "del", "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "pref", str(table_id + 1000)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", tun_name, "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", tun_name, "lookup", str(table_id), "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "iif", tun_name, "lookup", str(table_id), "pref", str(table_id + 1000)], capture_output=True)

def connect_node(tun: Tunnel, node: dict, region: Region = None):
    global dead_ips
    try:
        cfg_path = CONFIG_DIR / f"{tun.name}.ovpn"
        log_file = WORKSPACE / f"{tun.name}_err.log"
        cfg_path.write_text(node["config"], encoding="utf-8")
        
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        
        # 强制添加 --nobind 解除端口冲突，--route-nopull 剥夺路由修改权
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", tun.name, "--dev-type", "tun", 
               "--nobind", "--route-nopull",
               "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", 
               "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", 
               "--connect-timeout", "5", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
               
        with open(log_file, "w") as f: process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        
        success = False
        for _ in range(15):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except: pass
                
        if success and process.poll() is None:
            setup_routing(tun.name, tun.table_id)
            time.sleep(1) 
            
            # --- 穿透获取通道真实出口 IP ---
            true_ip = ""
            try:
                true_ip_res = subprocess.run(["curl", "-s", "-m", "10", "--interface", tun.name, "https://api.ipify.org"], capture_output=True, text=True)
                candidate_ip = true_ip_res.stdout.strip()
                if candidate_ip and candidate_ip.count('.') == 3:
                    true_ip = candidate_ip
            except: pass
            
            egress_ip = true_ip if true_ip else node['ip']
            
            if true_ip and true_ip != node['ip']:
                print(f"[*] {tun.name} 探测到真实出口 IP 与入口不一致: 入口 {node['ip']} -> 出口 {true_ip}", flush=True)

            is_residential = True
            try:
                # 兼容 testisp.info/api/check 的新解析逻辑
                req_url = f"https://testisp.info/api/check?ip={egress_ip}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, method="GET")
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    data = json.loads(check_res.read().decode("utf-8"))
                    isp_flag = str(data.get("isp", {}).get("flag", "")).lower()
                    
                    if isp_flag == "hosting":
                        is_residential = False
            except Exception as e: pass
            
            if not is_residential:
                print(f"[-] {tun.name} 节点出口 ({egress_ip}) 检测为机房 IP，残忍抛弃！", flush=True)
                dead_ips.add(node["ip"])
                try: process.terminate(); process.wait(2)
                except: process.kill()
                return

            print(f"[*] {tun.name} 进行流媒体质检 (YouTube)...", flush=True)
            res = subprocess.run(["curl", "-I", "-s", "-A", "Mozilla/5.0", "-m", "5", "--interface", tun.name, "https://www.youtube.com"], capture_output=True)
            if res.returncode != 0:
                print(f"[-] {tun.name} 节点出口无法连通 YouTube，拉黑更换: {node['ip']}", flush=True)
                dead_ips.add(node["ip"])
                try: process.terminate(); process.wait(2)
                except: process.kill()
                return

            with state_lock:
                tun.process = process
                tun.node = node
                tun.entry_ip = node["ip"]
                tun.egress_ip = egress_ip
                tun.country = node["country"]
                tun.connected_at = time.time()
                tun.ready = True
                if region:
                    proxy_server.ACTIVE_BINDS[region.port] = tun.name
                    role = "活跃" if proxy_server.ACTIVE_BINDS.get(region.port) == tun.name else "备用"
                    print(f"[+] 地区 [{region.idx}] {tun.name} ({role}) 就绪: 入口 {node['ip']} -> 出口 {egress_ip}", flush=True)
                else:
                    print(f"[+] {tun.name} 就绪: 入口 {node['ip']} -> 出口 {egress_ip}", flush=True)
        else:
            try: process.terminate(); process.wait(2)
            except: process.kill()
            dead_ips.add(node["ip"])
    finally:
        with state_lock: tun.is_connecting = False

def _health_check_region(reg):
    active_name = proxy_server.ACTIVE_BINDS.get(reg.port)
    if not active_name: return
    active_tun = reg.main if reg.main.name == active_name else reg.backup
    if not (active_tun.ready and active_tun.process and active_tun.process.poll() is None): return
    if time.time() - active_tun.connected_at <= 20: return
    target_tun = active_tun.name
    endpoints = ["http://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204", "http://1.1.1.1", "http://8.8.8.8"]
    is_alive = False
    for ep in endpoints:
        res = subprocess.run(["curl", "-I", "-s", "-m", "5", "--interface", target_tun, ep], capture_output=True)
        if res.returncode == 0:
            is_alive = True
            break
    if not is_alive:
        ping_res = subprocess.run(["ping", "-c", "2", "-W", "3", "-I", target_tun, "8.8.8.8"], capture_output=True)
        if ping_res.returncode == 0: is_alive = True
    return is_alive, active_tun

def health_check_loop():
    global dead_ips
    fail_counts = {}
    while True:
        time.sleep(15)
        with regions_lock:
            for reg in list(regions.values()):
                rid = reg.idx
                result = _health_check_region(reg)
                if result is None:
                    fail_counts[rid] = 0
                    continue
                is_alive, active_tun = result
                if not is_alive:
                    fail_counts[rid] = fail_counts.get(rid, 0) + 1
                    if fail_counts[rid] >= 3:
                        print(f"[!] 地区 [{rid}] {active_tun.name} 连续 {fail_counts[rid]} 次探针无响应，执行踢线: {active_tun.entry_ip}", flush=True)
                        dead_ips.add(active_tun.entry_ip)
                        proc_ref = active_tun.process
                        try: proc_ref.terminate(); proc_ref.wait(timeout=2)
                        except: proc_ref.kill()
                        with state_lock: active_tun.ready = False
                        fail_counts[rid] = 0
                    else:
                        print(f"[*] 地区 [{rid}] {active_tun.name} 探针无响应，复核容错 ({fail_counts[rid]}/3)...", flush=True)
                else:
                    fail_counts[rid] = 0

def get_best_candidate_for(country: str):
    with reservoir_lock:
        all_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x["ping"])
        candidates = [n for n in all_nodes if n["country"] == country and n["ip"] not in dead_ips]
        active_ips = set()
        for reg in regions.values():
            if reg.main.entry_ip: active_ips.add(reg.main.entry_ip)
            if reg.backup.entry_ip: active_ips.add(reg.backup.entry_ip)
        candidates = [n for n in candidates if n["ip"] not in active_ips]
        if not candidates:
            if any(n["country"] == country for n in all_nodes):
                dead_ips.clear()
                print(f"[!] ⚡ 紧急熔断：[{country}] 节点枯竭，解锁黑名单！", flush=True)
                candidates = [n for n in all_nodes if n["country"] == country and n["ip"] not in active_ips]
        if candidates: return candidates.pop(0)
    return None

def _maintain_region(reg):
    with state_lock:
        main_dead = (reg.main.process is None or reg.main.process.poll() is not None or not reg.main.ready)
        if main_dead:
            if reg.backup.ready and reg.backup.process and reg.backup.process.poll() is None:
                print(f"[*] ⚡ 地区 [{reg.idx}] 主通道暴毙，软开关秒切至备用: {reg.backup.egress_ip or reg.backup.entry_ip}", flush=True)
                reg.main, reg.backup = reg.backup, reg.main
                proxy_server.ACTIVE_BINDS[reg.port] = reg.main.name
                if reg.backup.process:
                    try: reg.backup.process.terminate(); reg.backup.process.wait(2)
                    except: reg.backup.process.kill()
                reg.backup.process = None; reg.backup.node = None; reg.backup.entry_ip = ""; reg.backup.egress_ip = ""
                reg.backup.ready = False; reg.backup.is_connecting = False
            else:
                if reg.main.process:
                    try: reg.main.process.terminate(); reg.main.process.wait(2)
                    except: reg.main.process.kill()
                reg.main.process = None; reg.main.ready = False; reg.main.is_connecting = False
                reg.main.entry_ip = ""; reg.main.egress_ip = ""
                proxy_server.ACTIVE_BINDS.pop(reg.port, None)
    with state_lock:
        needs_main = not reg.main.ready and not reg.main.is_connecting
        needs_backup = not reg.backup.ready and not reg.backup.is_connecting
    if needs_main:
        node = get_best_candidate_for(reg.country)
        if node:
            with state_lock: reg.main.is_connecting = True
            threading.Thread(target=connect_node, args=(reg.main, node, reg), daemon=True).start()
            time.sleep(1)
    elif needs_backup:
        node = get_best_candidate_for(reg.country)
        if node:
            with state_lock: reg.backup.is_connecting = True
            threading.Thread(target=connect_node, args=(reg.backup, node, reg), daemon=True).start()

def maintain_pool():
    global dead_ips, last_blacklist_clear
    while True:
        if time.time() - last_blacklist_clear > 600:
            dead_ips.clear()
            last_blacklist_clear = time.time()
        with reservoir_lock:
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips: global_node_reservoir.pop(ip, None)
        with regions_lock:
            for reg in list(regions.values()):
                _maintain_region(reg)
        time.sleep(2)

def main():
    global PROXY_PORT
    if os.geteuid() != 0: return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", "openvpn.*tun_r"], capture_output=True)
    
    try:
        req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
        with urllib.request.urlopen(req, timeout=10) as res:
            data = json.loads(res.read().decode("utf-8"))
            desired = data.get("regions", [])
            if not desired:
                desired = [{"idx": 0, "country": data.get("0", "JP"), "port": int(data.get("port", 7920))}]
            reconcile_regions(desired)
    except:
        reconcile_regions([{"idx": 0, "country": "JP", "port": 7920}])
    
    ports = [reg.port for reg in regions.values()]
    if not ports: ports = [7920]

    print("========================================", flush=True)
    print(f"  Proxy Controller 多地区引擎启动！地区: {len(regions)} 端口: {ports}", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=vpngate_fetch_loop, daemon=True).start()
    threading.Thread(target=update_config_loop, daemon=True).start()
    threading.Thread(target=proxy_server.start_proxy_server, args=("0.0.0.0", ports), daemon=True).start()
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
`;
      return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/agent") {
      const agentScript = `#!/usr/bin/env bash
echo "=========================================================="
echo "     Proxy Controller (Multi-Region Active-Standby)   "
echo "=========================================================="

# 彻底修复内核反向路径过滤导致备用通道回包被丢弃的问题
echo "net.ipv4.conf.all.rp_filter=2" > /etc/sysctl.d/99-proxy-lite.conf
echo "net.ipv4.conf.default.rp_filter=2" >> /etc/sysctl.d/99-proxy-lite.conf
sysctl --system >/dev/null 2>&1

apt-get update -q
apt-get install -y openvpn python3 curl iproute2 iptables cron psmisc

mkdir -p /opt/proxy_lite/configs
cd /opt/proxy_lite

echo "[1/3] 从安全中心拉取多地区双活极速引擎..."
curl -sLo lite_manager.py ${domain}/scripts/lite_manager.py
curl -sLo proxy_server.py ${domain}/scripts/proxy_server.py

echo "[2/3] 配置系统守护服务..."
cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=Proxy Core Engine (Active-Standby)
After=network.target

[Service]
Type=simple
Environment="PYTHONIOENCODING=utf-8"
Environment="LANG=C.UTF-8"
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-lite.service
systemctl restart proxy-lite.service

echo "[+] 引擎更新成功！多地区主备双活通道、异步刷IP逻辑已全量加载。"
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname.startsWith("/api/testisp-lookup/")) {
        if (!authenticate(request)) return unauthorizedResponse();
        const targetIp = url.pathname.replace("/api/testisp-lookup/", "");
        try {
            const reqUrl = `https://testisp.info/api/check?ip=${targetIp}`;
            const resp = await fetch(reqUrl, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "Accept": "application/json, text/plain, */*",
                    "Referer": "https://testisp.info/"
                }
            });
            const data = await resp.text();
            return new Response(data, { 
                status: resp.status,
                headers: { 
                    "Content-Type": resp.headers.get("content-type") || "application/json", 
                    "Access-Control-Allow-Origin": "*" 
                } 
            });
        } catch (err) {
            return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
        }
    }

    if (url.pathname === "/api/countries") {
        try {
            const response = await fetch("https://www.vpngate.net/api/iphone/");
            const text = await response.text();
            const lines = text.split('\n');
            const dynamicCountries = new Set();
            for (let i = 2; i < lines.length; i++) {
                const parts = lines[i].split(',');
                if (parts.length > 6) {
                    const country = parts[6];
                    if (country && country.length === 2 && country !== "xx" && country !== "--") {
                        dynamicCountries.add(country.toUpperCase());
                    }
                }
            }
            const predefinedCountries = ["US", "JP", "KR", "SG", "HK", "TW", "GB", "DE", "FR", "NL", "CA", "AU", "IN", "VN", "BR", "AE", "MY", "TH", "PH", "ID", "TR", "ZA", "IT", "ES", "RU", "CH", "SE", "PL", "NO", "DK", "FI", "IE", "AT", "NZ", "BE", "PT", "CZ", "GR", "HU", "RO", "BG", "HR", "SK", "SI", "LT", "LV", "EE", "UA", "RS", "BA", "CY", "MT", "IS", "LU"];
            const allCountries = new Set([...predefinedCountries, ...Array.from(dynamicCountries)]);
            return new Response(JSON.stringify(Array.from(allCountries).sort()), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        } catch(err) {
            return new Response(JSON.stringify(["US", "JP", "KR", "SG", "HK", "TW"]), { headers: { "Content-Type": "application/json" } }); 
        }
    }

    if (url.pathname === "/" || url.pathname === "/api/config" || url.pathname === "/api/nodes" || url.pathname === "/api/proxies" || url.pathname === "/api/report") {
      if (!authenticate(request)) return unauthorizedResponse();
    }

    if (url.pathname === "/api/config" && request.method === "GET") {
        const { results } = await env.DB.prepare(`SELECT value FROM global_config WHERE key = 'slot_map'`).all();
        if (results && results.length > 0) {
            const parsed = JSON.parse(results[0].value);
            if (!parsed.regions) {
                parsed.regions = [{ idx: 0, country: parsed["0"] || "JP", port: parsed.port || 7920, switch_trigger: parsed.switch_trigger || 0 }];
            }
            return new Response(JSON.stringify(parsed), { headers: { "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify({ regions: [{ idx: 0, country: "JP", port: 7920, switch_trigger: 0 }] }), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
        const data = await request.json();
        const regions = (data.regions || []).map((r, i) => ({
            idx: parseInt(r.idx) ?? i,
            country: (r.country || "JP").toUpperCase(),
            port: parseInt(r.port) || (7920 + i),
            switch_trigger: parseInt(r.switch_trigger) || 0
        }));
        if (regions.length === 0) {
            regions.push({ idx: 0, country: "JP", port: 7920, switch_trigger: 0 });
        }
        const ports = regions.map(r => r.port);
        if (new Set(ports).size !== ports.length) {
            return new Response("Error: duplicate ports", { status: 400 });
        }
        await env.DB.prepare(`INSERT INTO global_config (key, value) VALUES ('slot_map', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(JSON.stringify({ regions })).run();
        return new Response("OK");
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        await env.DB.prepare(`INSERT INTO servers (ip, details, last_seen) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET details = excluded.details, last_seen = excluded.last_seen`).bind(data.ip, JSON.stringify(data.details || []), Date.now()).run();
        if (data.logs) {
          await env.DB.prepare(`INSERT INTO server_logs (ip, logs, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET logs = excluded.logs, updated_at = excluded.updated_at`).bind(data.ip, data.logs, Date.now()).run();
        }
        return new Response("OK", { status: 200 });
      } catch (err) { return new Response("Error", { status: 500 }); }
    }

    if (url.pathname === "/api/proxies") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      if (results) {
        for (let server of results) {
          const details = JSON.parse(server.details || '[]');
          const byRegion = {};
          for (const d of details) {
            const ridx = d.region_idx ?? 0;
            if (!byRegion[ridx] || d.active) byRegion[ridx] = d;
          }
          for (const [ridx, d] of Object.entries(byRegion)) {
            proxyList.push(`socks5://${PROXY_USER}:${PROXY_PASS}@${server.ip}:${d.port}#${d.country}_r${ridx}_${d.node_ip || 'IP'}`);
          }
        }
      }
      return new Response(proxyList.join('\n'), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/api/nodes") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`
        SELECT s.*, l.logs 
        FROM servers s 
        LEFT JOIN server_logs l ON s.ip = l.ip 
        ORDER BY s.last_seen DESC
      `).all();
      return new Response(JSON.stringify(results || []), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/") {
      return new Response(DASHBOARD_HTML(domain, WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const DASHBOARD_HTML = (domain, webUser, webPass, proxyUser, proxyPass) => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Controller - 双活引擎总控</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.5); }
        ::-webkit-scrollbar-thumb { background: rgba(51, 65, 85, 0.8); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(71, 85, 105, 1); }
        input[type=number]::-webkit-inner-spin-button, 
        input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
    </style>
</head>
<body class="min-h-screen bg-[#090E17] text-slate-300 relative overflow-x-hidden selection:bg-indigo-500/30">
    <div class="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/20 blur-[120px] rounded-full pointer-events-none z-0"></div>
    <div class="fixed bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 blur-[120px] rounded-full pointer-events-none z-0"></div>

    <div class="max-w-7xl mx-auto p-6 relative z-10">
        <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-10 gap-6">
            <div>
                <h1 class="text-4xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 tracking-tight drop-shadow-sm">Proxy Controller</h1>
                <p class="text-slate-400 mt-2 text-sm flex items-center gap-2">
                    <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                    直链提取 API: <a href="/api/proxies" target="_blank" class="text-indigo-400 hover:text-indigo-300 border-b border-indigo-400/30 hover:border-indigo-300 transition-colors">${domain}/api/proxies</a>
                </p>
            </div>
            
            <div class="flex flex-col gap-3 w-full md:w-auto">
                <div class="bg-slate-900/80 backdrop-blur-md border border-slate-700/50 rounded-xl overflow-hidden shadow-lg">
                    <div class="bg-slate-800/50 px-4 py-2 border-b border-slate-700/50 flex items-center gap-2">
                        <div class="flex gap-1.5">
                            <div class="w-3 h-3 rounded-full bg-rose-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-amber-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                        </div>
                        <span class="text-xs text-slate-400 font-mono ml-2">VPS 纳管命令 (Root)</span>
                    </div>
                    <div class="p-3 bg-[#0D1117] text-sm font-mono text-emerald-400 select-all overflow-x-auto whitespace-nowrap">
                        bash <(curl -sL ${domain}/agent)
                    </div>
                </div>

                <div class="flex gap-4 text-xs font-mono">
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">面板凭证</span>
                        <span class="text-indigo-300 font-bold ml-4">${webUser} <span class="text-slate-600">/</span> ${webPass}</span>
                    </div>
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">代理凭证</span>
                        <span class="text-amber-300 font-bold ml-4">${proxyUser} <span class="text-slate-600">/</span> ${proxyPass}</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
            <div class="lg:col-span-1 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20">
                <div class="flex items-center gap-2 mb-4">
                    <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <h2 class="text-lg font-bold text-slate-200">全量国家代码库</h2>
                </div>
                <p class="text-xs text-slate-500 mb-4 leading-relaxed">系统已合并预设代码及实时的网络探测代码，提供最全面的目标锁定选择。</p>
                <div id="countries-list" class="flex flex-wrap gap-2 max-h-[160px] overflow-y-auto pr-1">
                    <span class="text-slate-600 text-sm animate-pulse">正在同步数据库...</span>
                </div>
            </div>

            <div class="lg:col-span-3 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20 flex flex-col justify-center relative overflow-hidden">
                <div class="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
                    <svg class="w-32 h-32" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                </div>
                
                <div class="mb-6 relative z-10">
                    <h2 class="text-2xl font-bold text-slate-100 tracking-wide mb-1 flex items-center gap-2">多地区主备双活引擎 <span class="bg-indigo-500/20 text-indigo-400 text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border border-indigo-500/30">Multi-Region</span></h2>
                    <p class="text-sm text-slate-400">每个地区独立运行主备双路隧道，支持动态增删，强制换 IP 时保留备用通道不中断业务。</p>
                </div>
                
                <div class="bg-slate-950/50 border border-slate-800/80 rounded-xl p-5 relative z-10">
                    <div class="flex items-center gap-3 mb-4 pb-4 border-b border-slate-800/50">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">全局端口:</span>
                        <input type="number" id="slot-port" value="7920" min="1024" max="65535" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-24 text-white font-bold text-lg text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="7920" />
                        <button onclick="saveAllRegions()" class="ml-auto group relative px-5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-sm font-bold shadow-lg shadow-blue-900/20 hover:shadow-indigo-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden">
                            <span class="flex items-center gap-2">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"></path></svg>
                                下发全部策略
                            </span>
                        </button>
                    </div>
                    <div id="regions-container" class="flex flex-col gap-3 mb-4"></div>
                    <button onclick="addRegion()" class="w-full py-2.5 rounded-lg border-2 border-dashed border-slate-700 text-slate-500 hover:text-indigo-400 hover:border-indigo-500/50 text-sm font-medium transition-colors flex items-center justify-center gap-2">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                        添加地区
                    </button>
                </div>
            </div>
        </div>
        
        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <div class="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse"></div>
                    活跃节点矩阵
                </h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-900/80 text-slate-400 text-xs uppercase tracking-wider">
                            <th class="py-4 px-6 font-medium w-1/5">母机宿主 IP</th>
                            <th class="py-4 px-6 font-medium">主备双路出口状态 (Active / Standby)</th>
                            <th class="py-4 px-6 font-medium w-32">心跳延迟</th>
                            <th class="py-4 px-6 font-medium text-right w-24">负载率</th>
                        </tr>
                    </thead>
                    <tbody id="nodes-table" class="divide-y divide-slate-800/50 text-sm">
                        <tr><td colspan="4" class="py-12 text-center text-slate-500">正在与 D1 数据库建立量子纠缠...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div id="ip-score-section" style="display: none;" class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    原生深度质检报告 (testisp.info)
                </h3>
                <a id="ip-score-link" href="#" class="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors">
                    原版页面 <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                </a>
            </div>
            
            <div id="native-score-container" class="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 bg-[#090E17]">
                <div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500">
                    <svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    <span>穿透请求中，正在构建原生质检报告...</span>
                </div>
            </div>
        </div>

        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 pb-8">
            <div class="px-4 py-3 border-b border-slate-800 bg-slate-900/80 flex justify-between items-center">
                <span class="text-xs text-slate-400 font-mono flex items-center gap-2">
                    <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M4 17h16a2 2 0 002-2V5a2 2 0 00-2-2H4a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                    VPS 实时运行日志 (Auto-Sync)
                </span>
                <span class="flex gap-1.5">
                    <div class="w-3 h-3 rounded-full bg-rose-500/80 shadow-[0_0_5px_rgba(244,63,94,0.5)]"></div>
                    <div class="w-3 h-3 rounded-full bg-amber-500/80 shadow-[0_0_5px_rgba(245,158,11,0.5)]"></div>
                    <div class="w-3 h-3 rounded-full bg-emerald-500/80 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div>
                </span>
            </div>
            <div class="p-4 h-64 overflow-y-auto bg-[#0D1117] font-mono text-[13px] leading-relaxed text-slate-300" id="terminal-output">
                <div class="text-slate-500 animate-pulse">等待 VPS 心跳回传日志数据...</div>
            </div>
        </div>
    </div>

    <script>
        let currentScoreIp = "";

        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const container = document.getElementById('countries-list');
                container.innerHTML = list.map(c => \`<span class="bg-slate-800/80 hover:bg-indigo-500/20 text-slate-300 hover:text-indigo-300 transition-colors border border-slate-700/50 px-2.5 py-1 rounded-md text-xs font-mono font-bold shadow-sm cursor-default">\${c}</span>\`).join('');
            } catch(e) {}
        }

        let allRegions = [{ idx: 0, country: "JP", port: 7920, switch_trigger: 0 }];

        function renderRegionCards() {
            const container = document.getElementById('regions-container');
            container.innerHTML = allRegions.map((r, i) => \`
                <div class="flex items-center gap-3 bg-slate-900/60 border border-slate-800 rounded-lg px-4 py-3" data-idx="\${r.idx}">
                    <span class="text-indigo-400 font-mono font-bold text-sm w-16 shrink-0">地区 \${r.idx}</span>
                    <input type="text" id="slot-cfg-\${r.idx}" value="\${r.country}" maxlength="2" class="bg-slate-800 border border-slate-700 rounded-lg py-1.5 w-14 text-white font-bold text-sm uppercase text-center focus:ring-2 focus:ring-indigo-500/50 outline-none" placeholder="JP" />
                    <input type="number" id="port-cfg-\${r.idx}" value="\${r.port}" min="1024" max="65535" class="bg-slate-800 border border-slate-700 rounded-lg py-1.5 w-20 text-white font-mono text-sm text-center focus:ring-2 focus:ring-indigo-500/50 outline-none" />
                    <button onclick="switchRegionIP(\${r.idx})" class="ml-auto px-3 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 text-white text-xs font-bold shadow hover:-translate-y-0.5 transition-all whitespace-nowrap">强制换IP</button>
                    \${allRegions.length > 1 ? \`<button onclick="removeRegion(\${r.idx})" class="px-2 py-1.5 rounded-lg bg-slate-800 text-rose-400 hover:bg-rose-500/20 text-xs font-bold border border-slate-700 transition-colors">✕</button>\` : ''}
                </div>
            \`).join('');
        }

        function collectRegions() {
            return allRegions.map(r => ({
                idx: r.idx,
                country: (document.getElementById(\`slot-cfg-\${r.idx}\`)?.value || 'JP').toUpperCase().trim(),
                port: parseInt(document.getElementById(\`port-cfg-\${r.idx}\`)?.value) || (7920 + r.idx),
                switch_trigger: r.switch_trigger || 0
            }));
        }

        async function loadConfig() {
            try {
                const res = await fetch('/api/config');
                const config = await res.json();
                allRegions = config.regions || [{ idx: 0, country: config["0"] || 'JP', port: config.port || 7920, switch_trigger: 0 }];
                document.getElementById('slot-port').value = allRegions[0]?.port || 7920;
                renderRegionCards();
            } catch(e) {}
        }

        async function saveAllRegions() {
            const regions = collectRegions();
            await fetch('/api/config', { method: 'POST', body: JSON.stringify({ regions }) });
            alert('🚀 全部地区策略已下发！Agent 将在下一心跳周期应用。');
        }

        async function switchRegionIP(idx) {
            const regions = collectRegions();
            const target = regions.find(r => r.idx === idx);
            if (target) target.switch_trigger = Date.now();
            await fetch('/api/config', { method: 'POST', body: JSON.stringify({ regions }) });
            alert(\`🔄 地区 [\${idx}] 强制换 IP 指令已下发！仅清退活跃通道，备用通道保持业务。\`);
        }

        function addRegion() {
            const maxIdx = allRegions.reduce((m, r) => Math.max(m, r.idx), -1);
            allRegions.push({ idx: maxIdx + 1, country: 'US', port: 7920 + maxIdx + 1, switch_trigger: 0 });
            renderRegionCards();
        }

        function removeRegion(idx) {
            if (allRegions.length <= 1) return;
            allRegions = allRegions.filter(r => r.idx !== idx);
            renderRegionCards();
        }

        async function loadNativeIpScore(ip) {
            const container = document.getElementById('native-score-container');
            container.innerHTML = '<div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500"><svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg><span>穿透请求中，正在构建原生质检报告...</span></div>';
            
            try {
                const res = await fetch('/api/testisp-lookup/' + encodeURIComponent(ip));
                const rawText = await res.text();
                
                let d;
                try {
                    d = JSON.parse(rawText);
                } catch (e) {
                    const safeText = rawText.substring(0, 500).replace(/</g, '&lt;').replace(/>/g, '&gt;');
                    throw new Error(\`目标接口返回了非 JSON 格式数据(可能 API 路径错误或被云端盾拦截)。<br>HTTP 状态码: \${res.status}<br><div class="mt-3 text-left bg-slate-900 p-3 rounded text-xs text-rose-300 font-mono break-all overflow-y-auto max-h-32 border border-rose-500/30">\${safeText}</div>\`);
                }
                
                if (!d || !d.geo || !d.isp) {
                    container.innerHTML = \`<div class="col-span-full text-center py-8 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">无法获取报告: 接口返回数据结构异常 \${d.error || ''}</div>\`;
                    return;
                }

                const isHosting = d.isp.flag === 'hosting';
                const threat = d.risk.threat_listed;
                const isNative = d.geo.is_native;
                
                const tags = isHosting 
                    ? '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-bold">机房IP</span>' 
                    : '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 text-xs font-bold">家庭宽带</span>';
                
                const locStr = [d.geo.country, d.geo.city].filter(Boolean).join(" ");
                const orgStr = d.isp.org || '-';

                container.innerHTML = \`
                    <div class="col-span-full bg-slate-800/60 border border-slate-700/80 p-5 rounded-2xl flex flex-wrap gap-4 justify-between items-center mb-2 shadow-lg">
                        <div class="flex items-center gap-4">
                            <span class="text-3xl font-extrabold font-mono text-white tracking-tight drop-shadow-sm">\${ip}</span>
                            <span class="text-slate-400 text-sm hidden sm:flex items-center border-l border-slate-700 pl-4 h-6">
                                <span class="uppercase tracking-widest text-indigo-400 mr-2 text-xs font-bold">\${d.geo.country_code || 'N/A'}</span> 
                                \${locStr} · \${orgStr}
                            </span>
                        </div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">基础物理画像</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">IP 原生性</span> <span class="font-medium text-sm">\${isNative ? '<span class="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold">原生 IP (Native)</span>' : \`<span class="px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-bold">\${d.geo.native_type || '广播 IP'}</span>\`}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">业务标记</span> <div class="flex gap-1">\${tags}</div></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">运营类型</span> <span class="font-medium \${isHosting ? 'text-rose-400' : 'text-emerald-400'} text-sm">\${d.isp.type || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">归属机构</span> <span class="font-medium text-slate-300 text-sm truncate max-w-[150px]" title="\${orgStr}">\${orgStr}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">ISP 网络底层</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">ASN</span> <span class="font-medium text-indigo-300 text-sm font-mono">\${d.isp.asn || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">解析时区</span> <span class="font-medium text-slate-300 text-sm font-mono">\${d.geo.timezone || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">偏移量 (Drift)</span> <span class="font-medium \${d.geo.has_drift ? 'text-rose-400' : 'text-emerald-400'} text-sm">\${d.geo.drift_km || 0} km</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">反向 DNS (rDNS)</span> <span class="font-medium text-slate-400 text-xs font-mono truncate max-w-[150px]" title="\${d.isp.rdns || '-'}">\${d.isp.rdns || '-'}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">风险深度检测</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">Spamhaus 情报</span> <span class="\${threat ? 'px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-bold' : 'px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold'}">\${threat ? '🚨 已在黑名单' : '✅ 纯净无异常'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">代理/机房特征</span> <span class="font-medium text-xs font-bold \${d.isp.warning ? 'text-amber-400' : 'text-emerald-400'} truncate max-w-[150px]" title="\${d.isp.warning || ''}">\${d.isp.warning || '未检测到明显异常'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">数据源</span> <span class="font-medium text-slate-400 text-xs">\${d.data_source || 'Unknown'}</span></div>
                    </div>
                \`;
            } catch (e) {
                container.innerHTML = \`<div class="col-span-full text-left p-6 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">\${e.message}</div>\`;
            }
        }

        async function fetchNodes() {
            try {
                const res = await fetch('/api/nodes');
                const servers = await res.json();
                const tbody = document.getElementById('nodes-table');
                const terminal = document.getElementById('terminal-output');
                
                if (!servers || servers.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="py-12 text-center text-slate-500 flex-col items-center justify-center"><svg class="w-12 h-12 mx-auto text-slate-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>未检测到在线母机，请在 VPS 运行纳管命令接入</td></tr>';
                    return;
                }

                tbody.innerHTML = servers.map(server => {
                    const details = JSON.parse(server.details || '[]');
                    const timeAgo = Math.floor((Date.now() - server.last_seen) / 1000);
                    
                    let proxyBadges = '';
                    if (details.length === 0) {
                        proxyBadges = \`
                        <div class="inline-flex items-center bg-slate-900 border border-amber-500/30 rounded-xl px-3 py-1.5 shadow-inner text-amber-400/90 text-sm">
                            <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-amber-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                            通道震荡熔断，正在全异步抢救拨号中...
                        </div>\`;
                    } else {
                        proxyBadges = '<div class="flex flex-col gap-2">' + details.map(d => {
                            const isActive = d.active;
                            const statusColorClass = isActive ? 'bg-emerald-500' : 'bg-sky-500';
                            const statusText = isActive ? 'ACTIVE (业务出口)' : 'STANDBY (热备就绪)';
                            const borderColorClass = isActive ? 'border-emerald-500/30' : 'border-sky-500/30';
                            const bgColorClass = isActive ? 'bg-emerald-500/10' : 'bg-sky-500/10';
                            const textColorClass = isActive ? 'text-emerald-400' : 'text-sky-400';
                            
                            return \`
                            <div class="inline-flex items-center bg-slate-950 border border-slate-800/80 rounded-xl px-2.5 py-1.5 shadow-inner">
                                <span class="bg-slate-800 text-slate-300 font-mono text-xs px-2 py-0.5 rounded-md mr-3 border border-slate-700 font-bold">\${d.tunnel}</span>
                                <span class="bg-indigo-500/20 text-indigo-400 font-bold font-mono text-xs px-2 py-0.5 rounded-md mr-3 border border-indigo-500/20">\${d.country}</span>
                                <span class="font-mono text-slate-300 text-sm tracking-wide mr-3" title="出口物理 IP">\${d.node_ip || '---.---.---.---'}:\${d.port}</span>
                                <span class="flex items-center gap-1.5 \${textColorClass} \${bgColorClass} px-2 py-0.5 rounded-md border \${borderColorClass} text-xs font-medium">
                                    <span class="w-1.5 h-1.5 rounded-full \${statusColorClass} shadow-[0_0_5px_currentColor]"></span> \${statusText}
                                </span>
                            </div>\`;
                        }).join('') + '</div>';
                    }

                    return \`
                        <tr class="hover:bg-slate-800/30 transition-colors group">
                            <td class="py-5 px-6 font-mono text-indigo-300 align-middle">
                                <div class="flex items-center gap-2">
                                    <svg class="w-4 h-4 text-slate-600 group-hover:text-indigo-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                                    \${server.ip}
                                </div>
                            </td>
                            <td class="py-5 px-6 align-middle">\${proxyBadges}</td>
                            <td class="py-5 px-6 align-middle">
                                <span class="flex items-center gap-1.5 \${timeAgo < 20 ? 'text-emerald-400' : 'text-rose-400'} font-mono text-xs">
                                    <span class="w-1.5 h-1.5 rounded-full \${timeAgo < 20 ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}"></span>
                                    \${timeAgo}s 前
                                </span>
                            </td>
                            <td class="py-5 px-6 align-middle text-right">
                                <span class="\${details.length >= 2 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : (details.length === 1 ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30')} py-1 px-3 rounded-md text-xs font-mono font-bold">
                                    \${details.length} 通道
                                </span>
                            </td>
                        </tr>
                    \`;
                }).join('');

                if (servers.length > 0 && servers[0].details) {
                    const details = JSON.parse(servers[0].details);
                    // 深度质检报告：永远提取正在承载业务的 ACTIVE 网卡 IP 进行评分
                    const activeNode = details.find(d => d.active) || details[0];
                    if (activeNode && activeNode.node_ip) {
                        const newIp = activeNode.node_ip;
                        if (newIp !== currentScoreIp) {
                            currentScoreIp = newIp;
                            document.getElementById('ip-score-section').style.display = 'block';
                            
                            // 针对 testisp.info 前端默认仅查本机的防呆机制：自动复制 IP 到剪贴板，跳转后由用户粘贴
                            const scoreLink = document.getElementById('ip-score-link');
                            scoreLink.href = \`https://testisp.info/?ip=\${newIp}\`;
                            scoreLink.onclick = (e) => {
                                e.preventDefault();
                                navigator.clipboard.writeText(newIp).then(() => {
                                    alert('🟢 已自动复制隧道节点 IP: ' + newIp + '\\n\\n由于 testisp.info 官网默认仅检测本机，请在随后打开的网页【输入框】中【粘贴】并回车查询！');
                                    window.open(\`https://testisp.info/?ip=\${newIp}\`, '_blank');
                                }).catch(() => {
                                    window.open(\`https://testisp.info/?ip=\${newIp}\`, '_blank');
                                });
                            };

                            loadNativeIpScore(newIp);
                        }
                    }
                }
                
                if (servers[0] && servers[0].logs) {
                    const isAtBottom = terminal.scrollHeight - terminal.scrollTop <= terminal.clientHeight + 30;
                    
                    let logHTML = servers[0].logs
                        .replace(/</g, '&lt;').replace(/>/g, '&gt;')
                        .replace(/\\[\\*\\]/g, '<span class="text-indigo-400 font-bold">[*]</span>')
                        .replace(/\\[\\+\\]/g, '<span class="text-emerald-400 font-bold">[+]</span>')
                        .replace(/\\[\\-\\]/g, '<span class="text-rose-400 font-bold">[-]</span>')
                        .replace(/\\[\\!\\]/g, '<span class="text-amber-400 font-bold">[!]</span>');
                        
                    terminal.innerHTML = '<pre class="whitespace-pre-wrap break-all">' + logHTML + '</pre>';
                    
                    if (isAtBottom) {
                        terminal.scrollTop = terminal.scrollHeight;
                    }
                }
                
            } catch (err) {}
        }
        
        fetchCountries();
        loadConfig();
        fetchNodes();
        setInterval(fetchNodes, 5000);
    </script>
</body>
</html>
`;
