import yaml
import os
import subprocess
from . import database
from . import proxy_parser

CONFIG_OUTPUT_PATH = "../config.yaml" # Default relative path
START_PORT = 10000

def generate_config_file(output_path=CONFIG_OUTPUT_PATH):
    sources = database.get_all_sources()
    all_proxies = []
    
    # Track issues for reporting
    issues = []  # List of {source_name, source_type, reason, detail}
    
    # 1. Collect all proxies
    for source in sources:
        if not source['enabled']:
            issues.append({
                'source_name': source['name'],
                'source_type': source['type'],
                'reason': 'disabled',
                'detail': 'Source is disabled'
            })
            continue
        
        stype = source['type']
        content = source['content']
        source_name = source['name']
        
        proxies = []
        try:
            if stype == 'subscription':
                proxies = proxy_parser.load_subscription(content)
                if not proxies:
                    issues.append({
                        'source_name': source_name,
                        'source_type': stype,
                        'reason': 'empty',
                        'detail': 'Subscription returned no proxies'
                    })
            elif stype in ('text', 'vless', 'yaml', 'http'):
                # Text/YAML/VLESS/HTTP all treated as text content containing proxies or config
                proxies = proxy_parser.parse_proxies_from_text(content)
                if not proxies:
                    issues.append({
                        'source_name': source_name,
                        'source_type': stype,
                        'reason': 'empty',
                        'detail': 'Content parsed but no valid proxies found'
                    })
        except Exception as e:
            issues.append({
                'source_name': source_name,
                'source_type': stype,
                'reason': 'error',
                'detail': str(e)
            })
            
        if proxies:
            all_proxies.extend(proxies)

    # 2. Port Management
    existing_mappings = database.get_all_mappings()
    # map: name -> port
    name_to_port_db = {m['proxy_name']: m['port'] for m in existing_mappings}
    used_ports = set(name_to_port_db.values())
    
    assigned_proxies = [] # list of (port, proxy_dict)
    
    # Deduplicate proxies by name? Or just unique names favored? 
    # Clash requires unique names. Let's assume user manages names. 
    # Or we can append index if duplicate.
    
    seen_names = set()
    
    for p in all_proxies:
        name = p.get("name")
        if not name:
            continue
            
        # Ensure unique name locally
        original_name = name
        idx = 1
        while name in seen_names:
            name = f"{original_name}_{idx}"
            idx += 1
        p["name"] = name
        seen_names.add(name)
        
        # Assign port
        if name in name_to_port_db:
            port = name_to_port_db[name]
        else:
            # Find next free port
            port = START_PORT
            while port in used_ports:
                port += 1
                if port > 65535:
                    raise RuntimeError(f"Port range exhausted: no available port between {START_PORT} and 65535")
            used_ports.add(port)
            database.save_port_mapping(name, port)
            
        assigned_proxies.append((port, p))
        
    assigned_proxies.sort(key=lambda x: x[0])
    
    # 3. Construct Config
    listeners = []
    proxy_groups = []
    proxies_list = []
    
    for port, p in assigned_proxies:
        proxies_list.append(p)
        group_name = f"PORT_{port}"
        
        listeners.append({
            "name": f"MIXED_{port}",
            "type": "mixed",
            "listen": "0.0.0.0",
            "port": port,
            "udp": True,
            "proxy": group_name,
        })
        
        proxy_groups.append({
            "name": group_name,
            "type": "select",
            "proxies": [p["name"]]
        })
        
    rules = ["MATCH,DIRECT"]
    
    final_config = {
        "external-controller": "0.0.0.0:9090",
        "external-ui": "dashboard",
        "secret": "orzboost",
        "mode": "rule",
        "log-level": "info",
        "socks-port": 7891,
        "listeners": listeners,
        "proxies": proxies_list,
        "proxy-groups": proxy_groups,
        "rules": rules
    }
    
    # Write to file
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(final_config, f, allow_unicode=True, sort_keys=False)
        
    return len(proxies_list), output_path, issues

def restart_mihomo_service(service_name="clash-meta"):
    try:
        subprocess.run(["systemctl", "restart", service_name], check=True)
        return True, "Service restarted successfully"
    except Exception as e:
        return False, str(e)

