import hashlib
import json

from . import database
from . import proxy_parser


def _stable_hash(parts):
    raw = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _proxy_identity(proxy):
    return [
        proxy.get("type"),
        proxy.get("server"),
        proxy.get("port"),
        proxy.get("uuid"),
        proxy.get("password"),
        proxy.get("public-key"),
        proxy.get("private-key"),
        proxy.get("name"),
    ]


def proxy_to_node(proxy, source_type):
    node_key = f"{source_type}:{_stable_hash(_proxy_identity(proxy))}"
    return {
        "node_key": node_key,
        "name": proxy.get("name", ""),
        "type": proxy.get("type", ""),
        "server": proxy.get("server", ""),
        "port": proxy.get("port"),
        "proxy": proxy,
        "metadata": {
            "server": proxy.get("server", ""),
            "port": proxy.get("port"),
            "source_type": source_type,
        },
    }


def _nodes_from_proxy_list(proxies, source_type):
    return [
        proxy_to_node(proxy, source_type)
        for proxy in proxies
        if isinstance(proxy, dict) and proxy.get("name")
    ]


def _load_protonvpn_nodes(content, source_name):
    try:
        from . import protonvpn_provider
    except Exception as exc:
        raise RuntimeError(f"ProtonVPN provider is unavailable: {exc}") from exc

    return protonvpn_provider.load_nodes(content, source_name)


def list_nodes(source_type, content, source_name=""):
    source_type = source_type or ""
    if source_type == "subscription":
        proxies = proxy_parser.load_subscription(content)
    elif source_type == "wireguard":
        proxies = proxy_parser.parse_wireguard_source(content, source_name)
    elif source_type == "xray":
        proxies, _port = proxy_parser.parse_xray_json(content)
    elif source_type == "protonvpn":
        return _load_protonvpn_nodes(content, source_name)
    elif source_type in ("text", "vless", "yaml", "http"):
        proxies = proxy_parser.parse_proxies_from_text(content)
    else:
        proxies = []

    return _nodes_from_proxy_list(proxies, source_type)


def apply_selection(nodes, selection):
    selection = database.normalize_selection(selection)
    mode = selection["mode"]
    selected_keys = set(selection["node_keys"])

    def matches_selected_key(node):
        keys = {node.get("node_key")}
        keys.update(node.get("selection_keys") or [])
        return bool(keys & selected_keys)

    if mode == "include":
        return [node for node in nodes if matches_selected_key(node)]
    if mode == "exclude":
        return [node for node in nodes if not matches_selected_key(node)]
    return nodes


def preview_nodes(source_type, content, selection=None, source_name=""):
    nodes = list_nodes(source_type, content, source_name)
    selection = database.normalize_selection(selection)
    selected = apply_selection(nodes, selection)
    selected_keys = {node["node_key"] for node in selected}

    preview = []
    for node in nodes:
        item = {
            "node_key": node["node_key"],
            "name": node["name"],
            "type": node["type"],
            "server": node["server"],
            "port": node["port"],
            "metadata": node.get("metadata", {}),
            "selected": node["node_key"] in selected_keys,
        }
        preview.append(item)

    return preview


def selected_proxies_for_source(source):
    nodes = list_nodes(source["type"], source["content"], source.get("name", ""))
    selected_nodes = apply_selection(nodes, source.get("selection"))
    return [node["proxy"] for node in selected_nodes]


def source_content_from_proton_configs(configs, username=""):
    return json.dumps({
        "username": username,
        "wireguard_configs": configs,
    }, ensure_ascii=False, indent=2)
