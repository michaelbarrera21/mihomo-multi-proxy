import yaml
import requests
import base64
from urllib.parse import urlparse, parse_qs, unquote
import json
import re

# 用于过滤订阅中的假代理条目（元数据注释）
FAKE_PROXY_KEYWORDS = [
    '剩余流量', '剩余', '重置', '套餐到期', '距离下次', '建议',
    '流量预警', '额度', '用量', '已用', '走失', '过期', '到期',
    'expire', 'traffic', 'remaining', 'reset', 'subscription'
]

def is_valid_proxy_entry(entry):
    """判断是否是有效代理条目（非元数据注释）"""
    if not isinstance(entry, dict):
        return False
    name = entry.get('name', '')
    if not name:
        return False
    for pattern in FAKE_PROXY_KEYWORDS:
        if pattern in name:
            return False
    return True

def load_subscription(url):
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        return parse_proxies_from_text(resp.text)
    except Exception as e:
        print(f"Error loading subscription {url}: {e}")
        return []

def parse_proxies_from_text(text):
    try:
        data = yaml.safe_load(text)
    except:
        data = None
        
    if isinstance(data, dict):
        proxies = data.get("proxies", [])
    elif isinstance(data, list):
        proxies = data
    elif isinstance(data, str):
        if looks_like_uri_subscription(data):
            proxies = parse_proxies_from_uri_lines(data)
        else:
            decoded = try_decode_base64_to_text(data)
            if decoded:
                proxies = parse_proxies_from_decoded_text(decoded)
            else:
                proxies = parse_proxies_from_decoded_text(data)
    else:
        # Fallback: maybe it's just a raw list of URIs in text
        proxies = parse_proxies_from_decoded_text(text)

    if not proxies:
        return []

    # Filter valid proxies and remove fake entries (metadata comments from providers)
    return [p for p in proxies if isinstance(p, dict) and p.get("name") and is_valid_proxy_entry(p)]

def try_decode_base64_to_text(data):
    if not isinstance(data, str):
        return None
    s = data.strip()
    if not s:
        return None
    try:
        # standard base64 often has padding issues or URL-safe variants
        fs = s.replace('-', '+').replace('_', '/')
        padding = len(fs) % 4
        if padding:
            fs += '=' * (4 - padding)
        decoded_bytes = base64.b64decode(fs, validate=False)
        decoded_text = decoded_bytes.decode("utf-8", errors="replace")
        return decoded_text.strip() if decoded_text else None
    except Exception:
        return None

def parse_proxies_from_decoded_text(decoded_text):
    # check if it looks like a list of URIs
    if looks_like_uri_subscription(decoded_text):
        return parse_proxies_from_uri_lines(decoded_text)
    
    # try parsing as YAML again if it was base64 decoded
    try:
        data2 = yaml.safe_load(decoded_text)
        if isinstance(data2, dict):
            proxies = data2.get("proxies", [])
            return proxies if isinstance(proxies, list) else []
        if isinstance(data2, list):
            return data2
    except:
        pass

    return []

def looks_like_uri_subscription(text):
    if not isinstance(text, str):
        return False
    s = text.strip()
    if not s:
        return False
    # If it contains typical yaml keys, it's likely yaml
    if "proxies:" in s[:200] or "proxy-groups:" in s[:200]:
        return False
    
    lines = s.splitlines()
    valid_schemes = ("trojan://", "ss://", "hysteria2://", "vless://", "vmess://", "http://", "https://")
    for line in lines[:5]: # check first few lines
        if line.strip().startswith(valid_schemes):
            return True
    return False

def parse_proxies_from_uri_lines(text):
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        p = None
        if line.startswith("trojan://"):
            p = parse_trojan_uri(line)
        elif line.startswith("ss://"):
            p = parse_ss_uri(line)
        elif line.startswith("hysteria2://"):
            p = parse_hysteria2_uri(line)
        elif line.startswith("vless://"):
            p = parse_vless_uri(line)
        elif line.startswith("http://") or line.startswith("https://"):
            p = parse_http_uri(line)
        
        if p and p.get("name"):
            proxies.append(p)
    return proxies

def parse_trojan_uri(uri):
    try:
        u = urlparse(uri)
        password = unquote(u.username) if u.username else ""
        server = u.hostname
        port = int(u.port) if u.port else None
        if not server or not port:
            return None
        q = parse_qs(u.query)
        name = unquote(u.fragment) if u.fragment else f"{server}:{port}"
        
        proxy = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
            "udp": True,
        }
        
        # SNI
        sni = (q.get("sni") or q.get("peer") or [None])[0]
        if sni and sni != "null":
            proxy["sni"] = sni
            
        # Allow Insecure
        allow_insecure = (q.get("allowInsecure") or q.get("allow_insecure") or [None])[0]
        if allow_insecure in ("1", "true", "True"):
            proxy["skip-cert-verify"] = True
            
        # Network & Transport Options
        network = (q.get("type") or ["tcp"])[0]
        if network != "tcp":
            proxy["network"] = network
            
        if network == "ws":
            ws_path = (q.get("path") or ["/"])[0]
            ws_host = (q.get("host") or [None])[0]
            proxy["ws-opts"] = {
                "path": ws_path
            }
            if ws_host:
                proxy["ws-opts"]["headers"] = {"Host": ws_host}
                
        elif network == "grpc":
            service_name = (q.get("serviceName") or [""])[0]
            if service_name:
                proxy["grpc-opts"] = {
                    "grpc-service-name": service_name
                }
        
        # Flow (e.g. for xtls-rprx-vision, though less common in pure trojan than vless)
        flow = (q.get("flow") or [None])[0]
        if flow:
            proxy["flow"] = flow

        return proxy
    except Exception:
        return None

def parse_ss_uri(uri):
    # (Existing logic from gen-config.py adjusted)
    try:
        name = None
        main = uri[len("ss://"):]
        if "#" in main:
            main, frag = main.split("#", 1)
            name = unquote(frag)
        
        query = ""
        if "?" in main:
            main, query = main.split("?", 1)

        info_part = main
        # Handle base64 parts
        if "@" in info_part:
            userinfo, hostport = info_part.split("@", 1)
            # if userinfo is base64
            if ":" not in userinfo:
                try:
                    userinfo = base64.b64decode(userinfo + "===", validate=False).decode("utf-8", errors="replace")
                except:
                    pass
            if ":" not in userinfo:
                return None
            method, password = userinfo.split(":", 1)
        else:
            # Everything might be base64
            try:
                decoded = base64.b64decode(main + "===", validate=False).decode("utf-8", errors="replace")
            except:
                return None
            if "@" not in decoded:
                return None
            userinfo, hostport = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)

        if ":" not in hostport:
             return None
        server, port_s = hostport.rsplit(":", 1)
        port = int(port_s)

        if not name:
            name = f"{server}:{port}"

        proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True,
        }
        
        if query:
            q = parse_qs(query)
            plugin = (q.get("plugin") or [None])[0]
            if plugin:
                # Simple plugin parser (obfs)
                # Clash META supports plugin/plugin-opts
                # This might need refinement based on exact SS format, but keep simple for now
                proxy["plugin"] = plugin
                # plugin-opts parsing would go here if needed
        return proxy
    except Exception:
        return None

def parse_hysteria2_uri(uri):
    try:
        u = urlparse(uri)
        server = u.hostname
        port = int(u.port) if u.port else None
        password = unquote(u.username) if u.username else ""
        if not server or not port:
            return None
        q = parse_qs(u.query)
        name = unquote(u.fragment) if u.fragment else f"{server}:{port}"
        
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,
            "udp": True,
        }
        sni = (q.get("sni") or [None])[0]
        if sni and sni != "null":
            proxy["sni"] = sni
        insecure = (q.get("insecure") or [None])[0]
        if insecure in ("1", "true", "True"):
            proxy["skip-cert-verify"] = True
        return proxy
    except Exception:
        return None

def parse_vless_uri(uri):
    # vless://uuid@host:port?params#name
    try:
        u = urlparse(uri)
        uuid = u.username
        server = u.hostname
        port = int(u.port) if u.port else 443
        
        if not server or not uuid:
            return None

        q = parse_qs(u.query)
        name = unquote(u.fragment) if u.fragment else f"{server}:{port}"
        
        # Common params
        type_ = (q.get("type") or ["tcp"])[0]
        security = (q.get("security") or ["none"])[0]
        
        proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": True,
            "tls": False,
            "network": type_
        }
        
        if security == "tls":
            proxy["tls"] = True
            sni = (q.get("sni") or [None])[0]
            if sni:
                proxy["servername"] = sni
            
            fp = (q.get("fp") or [None])[0]
            if fp:
                proxy["client-fingerprint"] = fp

        elif security == "reality":
            proxy["tls"] = True
            proxy["reality-opts"] = {}
            pbk = (q.get("pbk") or [None])[0]
            if pbk:
                proxy["reality-opts"]["public-key"] = pbk
            sid = (q.get("sid") or [None])[0]
            if sid:
                proxy["reality-opts"]["short-id"] = sid
            sni = (q.get("sni") or [None])[0]
            if sni:
                proxy["servername"] = sni # meta typically uses servername for sni in reality too
            
            fp = (q.get("fp") or [None])[0]
            if fp:
                proxy["client-fingerprint"] = fp

        # Flow (xtls-rprx-vision)
        flow = (q.get("flow") or [None])[0]
        if flow:
            proxy["flow"] = flow

        # Transport specifics
        if type_ == "ws":
            ws_path = (q.get("path") or ["/"])[0]
            ws_host = (q.get("host") or [None])[0]
            proxy["ws-opts"] = {
                "path": ws_path
            }
            if ws_host:
                 proxy["ws-opts"]["headers"] = {"Host": ws_host}
        
        if type_ == "grpc":
            service_name = (q.get("serviceName") or [""])[0]
            proxy["grpc-opts"] = {
                "grpc-service-name": service_name
            }

        return proxy
    except Exception as e:
        print(f"VLESS parse error: {e}")
        return None

def parse_http_uri(uri):
    """
    Parse HTTP/HTTPS proxy URI.
    Format: http://[username:password@]host:port?skip-cert-verify=true#name
    or: https://[username:password@]host:port?skip-cert-verify=true#name
    """
    try:
        u = urlparse(uri)
        server = u.hostname
        port = int(u.port) if u.port else (443 if u.scheme == "https" else 80)
        
        if not server:
            return None
        
        q = parse_qs(u.query)
        name = unquote(u.fragment) if u.fragment else f"{server}:{port}"
        
        proxy = {
            "name": name,
            "type": "http",
            "server": server,
            "port": port,
        }
        
        # Username/Password
        if u.username:
            proxy["username"] = unquote(u.username)
        if u.password:
            proxy["password"] = unquote(u.password)
        
        # HTTPS specific options
        if u.scheme == "https":
            proxy["tls"] = True
            
            # Skip cert verify (ignore certificate issues)
            skip_cert = (q.get("skip-cert-verify") or q.get("skip_cert_verify") or [None])[0]
            if skip_cert in ("1", "true", "True"):
                proxy["skip-cert-verify"] = True
            
            # SNI
            sni = (q.get("sni") or [None])[0]
            if sni and sni != "null":
                proxy["sni"] = sni
        
        
        return proxy
    except Exception as e:
        print(f"HTTP/HTTPS parse error: {e}")
        return None

def extract_mappings_from_config(config_text):
    """
    Parses a full config.yaml text and extracts port mappings based on listeners
    and proxy-groups.
    Returns: dict {proxy_name: port}
    """
    try:
        config = yaml.safe_load(config_text)
        if not isinstance(config, dict):
            return {}
            
        listeners = config.get("listeners", [])
        proxy_groups = config.get("proxy-groups", [])
        
        # group_name -> proxy_name (assuming 1-to-1 mapping for our generated groups)
        group_to_proxy = {}
        for g in proxy_groups:
            gname = g.get("name")
            proxies = g.get("proxies", [])
            if gname and proxies:
                # We assume the first proxy in the group is the target
                group_to_proxy[gname] = proxies[0]
                
        mappings = {}
        for l in listeners:
            port = l.get("port")
            proxy_group = l.get("proxy")
            if port and proxy_group:
                proxy_name = group_to_proxy.get(proxy_group)
                if proxy_name:
                    mappings[proxy_name] = port
                    
        return mappings
    except Exception as e:
        print(f"Error extracting mappings: {e}")
        return {}

import re

# ... existing imports ...

def strip_json_comments(text):
    """
    Strips C-style // comments from JSON text, being careful not to strip URLs.
    """
    lines = text.splitlines()
    cleaned = []
    for line in lines:
        if "//" in line:
            # Heuristic: if :// is present, it's likely a URL, don't strip
            # Ideally we should use a proper parser step, but for config files 
            # this is usually sufficient.
            if "://" in line:
                cleaned.append(line)
            else:
                cleaned.append(line.split("//")[0])
        else:
            cleaned.append(line)
    return "\n".join(cleaned)

def parse_xray_json(content):
    """
    Parses Xray JSON content to extract proxies and inbound port.
    Returns: (proxies: list[dict], inbound_port: int|None)
    """
    try:
        # Strip comments first
        clean_content = strip_json_comments(content)
        data = json.loads(clean_content)
        
        # 1. Extract Inbound Port
        port = None
        inbounds = data.get("inbounds", [])
        if isinstance(inbounds, list):
            for ib in inbounds:
                if ib.get("protocol") in ("socks", "http", "mixed"):
                    p = ib.get("port")
                    if p:
                        port = int(p)
                        break
        
        # 2. Extract Outbounds
        proxies = []
        outbounds = data.get("outbounds", [])
        if isinstance(outbounds, list):
            for i, ob in enumerate(outbounds):
                protocol = ob.get("protocol")
                settings = ob.get("settings", {})
                stream = ob.get("streamSettings", {})
                tag = ob.get("tag", f"proxy_{i}")
                
                if protocol == "vless":
                    vnext = settings.get("vnext", [])
                    if vnext and len(vnext) > 0:
                        server_info = vnext[0]
                        address = server_info.get("address")
                        port_out = server_info.get("port")
                        users = server_info.get("users", [])
                        if users:
                            user = users[0]
                            uuid = user.get("id")
                            flow = user.get("flow")
                            
                            network = stream.get("network", "tcp")
                            if network == "raw": 
                                network = "tcp"

                            proxy = {
                                "name": tag,
                                "type": "vless",
                                "server": address,
                                "port": port_out,
                                "uuid": uuid,
                                "udp": True,
                                "tls": True, # Assume reality implies TLS
                                "network": network
                            }
                            
                            if flow:
                                proxy["flow"] = flow
                                
                            security = stream.get("security")
                            if security == "reality":
                                reality = stream.get("realitySettings", {})
                                proxy["servername"] = reality.get("serverName")
                                proxy["client-fingerprint"] = reality.get("fingerprint")
                                proxy["reality-opts"] = {
                                    "public-key": reality.get("publicKey"),
                                    "short-id": reality.get("shortId"),
                                }
                                if reality.get("spiderX"):
                                     proxy["reality-opts"]["spider-x"] = reality.get("spiderX")
                                     
                            proxies.append(proxy)
                            
        return proxies, port
    except Exception as e:
        print(f"Error parsing Xray JSON: {e}")
        return [], None
