import base64
import hashlib
import json
import re
import secrets
from datetime import datetime, timezone

import requests

from . import proxy_parser
from . import source_providers

PROTON_WG_IPV4 = "10.2.0.2"
PROTON_WG_IPV4_DNS = "10.2.0.1"
PROTON_WG_IPV6 = "2a07:b944::2:2"
PROTON_WG_IPV6_DNS = "2a07:b944::2:1"
PROTON_WG_MTU = 1420

PROTON_SUCCESS_CODE = 1000
PROTON_DEFAULT_APP_VERSION = "linux-vpn-cli@5.1.2"
PROTON_API_BASE_URLS = [
    "https://api.protonvpn.ch",
    "https://vpn-api.proton.me",
    "https://account.protonvpn.com/api",
]
PROTON_DEFAULT_WG_PORTS = [443, 88, 1224, 51820, 500, 4500]
PROTON_DEFAULT_DEDUPE_ENDPOINTS = True
PROTON_ALIAS_SAMPLE_LIMIT = 12

SRP_BIT_LENGTH = 2048
SRP_GENERATOR = 2
BCRYPT_ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
STD_B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

FEATURE_BITS = {
    1 << 0: "secure_core",
    1 << 1: "tor",
    1 << 2: "p2p",
    1 << 3: "streaming",
    1 << 4: "ipv6",
}


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


class ProtonAPIError(RuntimeError):
    def __init__(self, message, status_code=None, api_code=None):
        super().__init__(message)
        self.status_code = status_code
        self.api_code = api_code


def _load_content_config(content):
    try:
        data = json.loads(content or "{}")
    except Exception as exc:
        raise RuntimeError("ProtonVPN source content must be JSON") from exc

    if not isinstance(data, dict):
        raise RuntimeError("ProtonVPN source content must be a JSON object")
    return data


def _load_wireguard_configs(data, source_name):
    configs = data.get("wireguard_configs")
    if not configs:
        return []

    proxies = []
    for index, item in enumerate(configs, start=1):
        if isinstance(item, str):
            conf_text = item
            name = f"{source_name} #{index}" if len(configs) > 1 else source_name
        elif isinstance(item, dict):
            conf_text = item.get("config") or item.get("content") or ""
            name = item.get("name") or f"{source_name} #{index}"
        else:
            continue
        parsed = proxy_parser.parse_wireguard_config(conf_text, name)
        metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
        for proxy in parsed:
            proxy["_metadata"] = metadata
            proxies.append(proxy)

    nodes = []
    for proxy in proxies:
        if not proxy.get("name"):
            continue
        node = source_providers.proxy_to_node(proxy, "protonvpn")
        node["metadata"].update(proxy.pop("_metadata", {}) or {})
        nodes.append(node)

    return nodes


def _feature_names_from_bitmap(value):
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        value = 0
    return [name for bit, name in FEATURE_BITS.items() if value & bit]


def _build_wireguard_config(proxy):
    addresses = [f"{PROTON_WG_IPV4}/32"]
    dns = [PROTON_WG_IPV4_DNS]
    if proxy.get("ipv6"):
        addresses.append(f"{PROTON_WG_IPV6}/128")
        dns.append(PROTON_WG_IPV6_DNS)

    return "\n".join([
        "[Interface]",
        f"PrivateKey = {proxy['private-key']}",
        f"Address = {', '.join(addresses)}",
        f"DNS = {', '.join(dns)}",
        f"MTU = {PROTON_WG_MTU}",
        "",
        "[Peer]",
        f"PublicKey = {proxy['public-key']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {proxy['server']}:{proxy['port']}",
        "PersistentKeepalive = 25",
        "",
    ])


def _node_to_config_item(node):
    proxy = node["proxy"]
    metadata = dict(node.get("metadata") or {})
    return {
        "name": proxy["name"],
        "config": _build_wireguard_config(proxy),
        "metadata": metadata,
    }


def _node_to_compact_server(node):
    proxy = node["proxy"]
    metadata = dict(node.get("metadata") or {})
    metadata.pop("server", None)
    metadata.pop("port", None)
    metadata.pop("source_type", None)
    metadata.pop("alias_node_keys", None)

    return {
        "name": proxy["name"],
        "server": proxy["server"],
        "public_key": proxy["public-key"],
        "port": proxy.get("port"),
        "ipv6": bool(proxy.get("ipv6")),
        "metadata": metadata,
    }


def _auth_value(auth, *keys):
    if not isinstance(auth, dict):
        return ""
    for key in keys:
        value = auth.get(key)
        if value is not None:
            return str(value).strip()
    return ""


def _stored_auth_for_content(auth):
    if not isinstance(auth, dict):
        return None

    uid = _auth_value(auth, "uid", "UID")
    refresh_token = _auth_value(auth, "refresh_token", "RefreshToken")
    if not uid or not refresh_token:
        return None

    stored = {
        "uid": uid,
        "refresh_token": refresh_token,
        "api_base_url": _auth_value(auth, "api_base_url", "base_url") or PROTON_API_BASE_URLS[0],
        "app_version": _auth_value(auth, "app_version") or PROTON_DEFAULT_APP_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    username = _auth_value(auth, "username")
    if username:
        stored["username"] = username
    return stored


def _serialize_nodes_to_content(nodes, username="", auth=None, stats=None, filters=None):
    stored_auth = _stored_auth_for_content(auth)
    if nodes:
        first_proxy = nodes[0]["proxy"]
        payload = {
            "format": "protonvpn.compact.v1",
            "username": username,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        if stored_auth:
            payload["auth"] = stored_auth
        if filters:
            payload["filters"] = filters
        if stats:
            payload["stats"] = stats
        payload["wireguard"] = {
            "private_key": first_proxy["private-key"],
            "port": first_proxy.get("port", PROTON_DEFAULT_WG_PORTS[0]),
            "ipv4": PROTON_WG_IPV4,
            "ipv4_dns": PROTON_WG_IPV4_DNS,
            "ipv6": PROTON_WG_IPV6,
            "ipv6_dns": PROTON_WG_IPV6_DNS,
            "mtu": PROTON_WG_MTU,
        }
        payload["servers"] = [_node_to_compact_server(node) for node in nodes]
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    payload = {
        "username": username,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "wireguard_configs": [_node_to_config_item(node) for node in nodes],
    }
    if stored_auth:
        payload["auth"] = stored_auth
    if filters:
        payload["filters"] = filters
    if stats:
        payload["stats"] = stats
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _dedupe_endpoints_enabled(data):
    filters = data.get("filters")
    if isinstance(filters, dict) and "dedupe_endpoints" in filters:
        return _as_bool(filters.get("dedupe_endpoints"), PROTON_DEFAULT_DEDUPE_ENDPOINTS)
    if "dedupe_endpoints" in data:
        return _as_bool(data.get("dedupe_endpoints"), PROTON_DEFAULT_DEDUPE_ENDPOINTS)
    return PROTON_DEFAULT_DEDUPE_ENDPOINTS


def _proton_filter_config(data):
    return {"dedupe_endpoints": _dedupe_endpoints_enabled(data)}


def _proton_endpoint_key(node):
    proxy = node.get("proxy") or {}
    public_key = proxy.get("public-key") or proxy.get("public_key")
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not public_key:
        return None
    return (
        proxy.get("type") or "wireguard",
        str(server),
        str(port or ""),
        str(public_key),
    )


def _natural_server_name_key(value):
    value = str(value or "")
    match = re.match(r"^(.*)#(\d+)$", value)
    if match:
        return (match.group(1).lower(), int(match.group(2)), value.lower())
    return (value.lower(), -1, value.lower())


def _representative_sort_key(node):
    metadata = node.get("metadata") or {}
    server_name = metadata.get("server_name") or node.get("name") or ""
    logical_id = metadata.get("logical_id") or ""
    return (_natural_server_name_key(server_name), str(logical_id))


def _number_values(nodes, key):
    values = []
    for node in nodes:
        metadata = node.get("metadata") or {}
        try:
            value = float(metadata.get(key))
        except (TypeError, ValueError):
            continue
        values.append(value)
    return values


def _dedupe_proton_endpoint_nodes(nodes):
    groups = {}
    order = []
    passthrough = []
    for node in nodes:
        key = _proton_endpoint_key(node)
        if not key:
            passthrough.append(node)
            continue
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(node)

    deduped = []
    duplicate_count = 0
    max_group_size = 1
    for key in order:
        group = sorted(groups[key], key=_representative_sort_key)
        representative = group[0]
        if len(group) > 1:
            duplicate_count += len(group) - 1
            max_group_size = max(max_group_size, len(group))
            metadata = representative.setdefault("metadata", {})
            names = [node.get("name") for node in group if node.get("name")]
            server_names = [
                (node.get("metadata") or {}).get("server_name")
                for node in group
                if (node.get("metadata") or {}).get("server_name")
            ]
            logical_ids = [
                (node.get("metadata") or {}).get("logical_id")
                for node in group
                if (node.get("metadata") or {}).get("logical_id")
            ]
            physical_ids = [
                (node.get("metadata") or {}).get("physical_id")
                for node in group
                if (node.get("metadata") or {}).get("physical_id")
            ]
            loads = _number_values(group, "load")
            scores = _number_values(group, "score")
            metadata.update({
                "deduped_endpoint": True,
                "logical_count": len(group),
                "alias_names": names[:PROTON_ALIAS_SAMPLE_LIMIT],
                "alias_server_names": server_names[:PROTON_ALIAS_SAMPLE_LIMIT],
                "alias_sample_truncated": len(names) > PROTON_ALIAS_SAMPLE_LIMIT,
                "logical_id_count": len(set(logical_ids)),
                "physical_id_count": len(set(physical_ids)),
            })
            if loads:
                metadata["load_min"] = min(loads)
                metadata["load_max"] = max(loads)
            if scores:
                metadata["score_min"] = min(scores)
                metadata["score_max"] = max(scores)
            representative["selection_keys"] = [node["node_key"] for node in group if node.get("node_key")]
        deduped.append(representative)

    deduped.extend(passthrough)
    stats = {
        "raw_servers": len(nodes),
        "unique_endpoints": len(deduped),
        "deduped_servers": duplicate_count,
        "max_logicals_per_endpoint": max_group_size,
    }
    return deduped, stats


def _apply_proton_node_filters(nodes, data):
    if not _dedupe_endpoints_enabled(data):
        return nodes, {
            "raw_servers": len(nodes),
            "unique_endpoints": len(nodes),
            "deduped_servers": 0,
            "max_logicals_per_endpoint": 1,
        }
    return _dedupe_proton_endpoint_nodes(nodes)


def _load_compact_servers(data):
    servers = data.get("servers")
    wireguard = data.get("wireguard")
    if not isinstance(servers, list) or not isinstance(wireguard, dict):
        return []

    private_key = wireguard.get("private_key")
    default_port = wireguard.get("port") or PROTON_DEFAULT_WG_PORTS[0]
    if not private_key:
        return []

    nodes = []
    for item in servers:
        if not isinstance(item, dict):
            continue
        server = item.get("server")
        public_key = item.get("public_key")
        name = item.get("name")
        if not server or not public_key or not name:
            continue

        has_ipv6 = bool(item.get("ipv6"))
        proxy = {
            "name": name,
            "type": "wireguard",
            "server": server,
            "port": item.get("port") or default_port,
            "private-key": private_key,
            "public-key": public_key,
            "ip": wireguard.get("ipv4") or PROTON_WG_IPV4,
            "allowed-ips": ["0.0.0.0/0", "::/0"],
            "dns": [wireguard.get("ipv4_dns") or PROTON_WG_IPV4_DNS],
            "remote-dns-resolve": True,
            "udp": True,
            "mtu": wireguard.get("mtu") or PROTON_WG_MTU,
        }
        if has_ipv6:
            proxy["ipv6"] = wireguard.get("ipv6") or PROTON_WG_IPV6
            proxy["dns"] = [
                wireguard.get("ipv4_dns") or PROTON_WG_IPV4_DNS,
                wireguard.get("ipv6_dns") or PROTON_WG_IPV6_DNS,
            ]

        node = source_providers.proxy_to_node(proxy, "protonvpn")
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        node["metadata"].update(metadata)
        nodes.append(node)

    nodes, _stats = _apply_proton_node_filters(nodes, data)
    return nodes


def _base_api_headers(app_version=None):
    return {
        "Accept": "application/vnd.protonmail.v1+json",
        "Content-Type": "application/json",
        "User-Agent": "ProtonVPN/5.1.2 (Linux; debian/12)",
        "x-pm-apiversion": "3",
        "x-pm-appversion": app_version or PROTON_DEFAULT_APP_VERSION,
    }


def _make_session(base_url, app_version=None):
    session = requests.Session()
    session.headers.update(_base_api_headers(app_version))
    session.proton_base_url = base_url.rstrip("/")
    session.proton_app_version = app_version or PROTON_DEFAULT_APP_VERSION
    session.proton_auth = None
    return session


def _api_url(session, path):
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{session.proton_base_url}{path}"


def _extract_api_error(data, fallback):
    if isinstance(data, dict):
        return data.get("Error") or data.get("error") or data.get("Message") or fallback
    return fallback


def _request_json(session, method, path, **kwargs):
    response = session.request(method, _api_url(session, path), timeout=45, **kwargs)
    try:
        data = response.json()
    except ValueError:
        data = None

    if response.status_code >= 400:
        detail = _extract_api_error(data, response.text[:300])
        api_code = data.get("Code") if isinstance(data, dict) else None
        raise ProtonAPIError(
            f"Proton API {response.status_code}: {detail}",
            status_code=response.status_code,
            api_code=api_code,
        )

    if isinstance(data, dict):
        code = data.get("Code")
        if code is not None and code != PROTON_SUCCESS_CODE:
            raise ProtonAPIError(
                _extract_api_error(data, f"Proton API error code {code}"),
                status_code=response.status_code,
                api_code=code,
            )
        return data

    return data or {}


def _apply_bearer_auth(session, uid, access_token):
    session.headers.update({
        "Authorization": f"Bearer {access_token}",
        "x-pm-uid": uid,
    })


def _auth_from_response(auth_response, session, username="", fallback_refresh_token=""):
    if not isinstance(auth_response, dict):
        return None

    uid = _auth_value(auth_response, "UID", "uid")
    access_token = _auth_value(auth_response, "AccessToken", "access_token")
    refresh_token = (
        _auth_value(auth_response, "RefreshToken", "refresh_token")
        or fallback_refresh_token
    )
    if not uid and "x-pm-uid" in session.headers:
        uid = session.headers["x-pm-uid"]
    if not uid or not refresh_token:
        return None

    auth = {
        "uid": uid,
        "refresh_token": refresh_token,
        "api_base_url": session.proton_base_url,
        "app_version": getattr(session, "proton_app_version", PROTON_DEFAULT_APP_VERSION),
    }
    if access_token:
        auth["access_token"] = access_token
    if username:
        auth["username"] = username
    return auth


def _auth_from_existing_content(content):
    if not content:
        return None
    try:
        data = json.loads(content)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    auth = data.get("auth")
    if not isinstance(auth, dict):
        return None

    stored = dict(auth)
    if data.get("username") and not stored.get("username"):
        stored["username"] = data.get("username")
    return stored


def _stored_auth_from_data(data):
    for key in ("stored_auth", "auth"):
        auth = data.get(key)
        if isinstance(auth, dict):
            return dict(auth)
    return _auth_from_existing_content(data.get("existing_content"))


def _has_explicit_session_credentials(data):
    cookie_header = (data.get("cookie_header") or "").strip()
    auth_uid = (data.get("auth_uid") or "").strip()
    auth_token = (data.get("auth_token") or "").strip()
    access_token = (data.get("access_token") or "").strip()
    return bool(cookie_header or access_token or (auth_uid and auth_token))


def _login_with_saved_auth(base_url, auth, app_version=None):
    effective_app_version = app_version or _auth_value(auth, "app_version") or PROTON_DEFAULT_APP_VERSION
    session = _make_session(base_url, effective_app_version)
    uid = _auth_value(auth, "uid", "UID")
    refresh_token = _auth_value(auth, "refresh_token", "RefreshToken")
    if not uid or not refresh_token:
        raise RuntimeError(
            "Stored Proton session is missing UID or RefreshToken. "
            "Please fetch once with username/password and 2FA."
        )

    session.headers["x-pm-uid"] = uid
    refreshed = _request_json(
        session,
        "POST",
        "/auth/refresh",
        json={
            "UID": uid,
            "RefreshToken": refresh_token,
        },
    )
    refreshed_auth = _auth_from_response(
        refreshed,
        session,
        username=_auth_value(auth, "username"),
        fallback_refresh_token=refresh_token,
    )
    access_token = _auth_value(refreshed, "AccessToken", "access_token")
    refreshed_uid = _auth_value(refreshed, "UID", "uid") or uid
    if not access_token:
        raise ProtonAPIError("Proton refresh response did not include an access token")

    _apply_bearer_auth(session, refreshed_uid, access_token)
    session.proton_auth = refreshed_auth
    return session


def _bcrypt_base64(data):
    translated = base64.b64encode(data).translate(
        bytes.maketrans(STD_B64_ALPHABET, BCRYPT_ALPHABET)
    )
    return translated.rstrip(b"=").decode("ascii")


def _bcrypt_hash(password, encoded_salt):
    try:
        import bcrypt
    except Exception as exc:
        raise RuntimeError(
            "Built-in Proton username/password login requires the bcrypt "
            "Python package. Run pip install -r requirements.txt, or use "
            "Proton session-cookie mode."
        ) from exc

    if len(encoded_salt) < 22:
        raise RuntimeError("Proton auth salt is shorter than bcrypt expects")

    salt_22 = encoded_salt[:22].encode("ascii")
    password_bytes = password.encode("utf-8")
    salt_2y = b"$2y$10$" + salt_22
    try:
        return bcrypt.hashpw(password_bytes, salt_2y)
    except ValueError:
        # pyca/bcrypt historically prefers $2b$; the hash bytes are otherwise
        # compatible with Proton's $2y$ flow, so restore the expected prefix.
        try:
            hashed = bcrypt.hashpw(password_bytes, b"$2b$10$" + salt_22)
        except ValueError as exc:
            raise RuntimeError(
                "Proton auth returned a bcrypt salt shape that this bcrypt "
                "runtime rejected."
            ) from exc
        return b"$2y$" + hashed[4:]


def _expand_hash(data):
    parts = []
    for index in range(4):
        parts.append(hashlib.sha512(data + bytes([index])).digest())
    return b"".join(parts)


def _strip_signed_modulus(signed_modulus):
    value = (signed_modulus or "").strip()
    if "BEGIN PGP SIGNED MESSAGE" not in value:
        return value

    lines = value.replace("\r\n", "\n").split("\n")
    body = []
    in_body = False
    for line in lines:
        if line.startswith("-----BEGIN PGP SIGNATURE-----"):
            break
        if in_body:
            body.append(line)
            continue
        if line == "":
            in_body = True
    return "\n".join(body).strip()


def _hash_password(version, username, password, salt_b64, signed_modulus):
    modulus_text = _strip_signed_modulus(signed_modulus)
    modulus = base64.b64decode(modulus_text)

    if version in (3, 4):
        salt = base64.b64decode(salt_b64)
        encoded_salt = _bcrypt_base64(salt + b"proton")
    else:
        raise RuntimeError(
            f"Unsupported Proton auth password version {version}; "
            "modern Proton accounts should use version 3 or 4."
        )

    crypted = _bcrypt_hash(password, encoded_salt)
    return _expand_hash(crypted + modulus), modulus


def _to_le_int(data):
    return int.from_bytes(data, "little")


def _from_le_int(value, length):
    return int(value).to_bytes(length, "little")


def _check_srp_params(modulus, server_ephemeral):
    modulus_int = _to_le_int(modulus)
    server_int = _to_le_int(server_ephemeral)
    modulus_minus_one = modulus_int - 1

    if modulus_int.bit_length() != SRP_BIT_LENGTH:
        raise RuntimeError("Proton SRP modulus has an unexpected size")
    if modulus_int % 8 != 3:
        raise RuntimeError("Proton SRP modulus failed validation")
    if server_int <= 1 or server_int >= modulus_minus_one:
        raise RuntimeError("Proton SRP server ephemeral is out of bounds")
    if pow(SRP_GENERATOR, modulus_int >> 1, modulus_int) != modulus_minus_one:
        raise RuntimeError("Proton SRP modulus primality check failed")

    return modulus_int, server_int


def _generate_client_secret(modulus_int):
    modulus_minus_one = modulus_int - 1
    lower_bound = SRP_BIT_LENGTH * 2
    while True:
        secret = secrets.randbelow(modulus_minus_one)
        if lower_bound < secret < modulus_minus_one:
            return secret


def _generate_srp_proofs(version, username, password, salt_b64, signed_modulus, server_ephemeral_b64):
    hashed_password, modulus = _hash_password(
        version, username, password, salt_b64, signed_modulus
    )
    server_ephemeral = base64.b64decode(server_ephemeral_b64)
    modulus_int, server_int = _check_srp_params(modulus, server_ephemeral)

    length = len(modulus)
    generator = SRP_GENERATOR
    modulus_minus_one = modulus_int - 1

    hashed_password_int = _to_le_int(hashed_password)
    while True:
        client_secret = _generate_client_secret(modulus_int)
        client_ephemeral_int = pow(generator, client_secret, modulus_int)
        client_ephemeral = _from_le_int(client_ephemeral_int, length)
        scramble = _to_le_int(_expand_hash(client_ephemeral + server_ephemeral))
        if scramble != 0:
            break

    multiplier = _to_le_int(
        _expand_hash(_from_le_int(generator, length) + _from_le_int(modulus_int, length))
    ) % modulus_int
    if multiplier <= 1 or multiplier >= modulus_minus_one:
        raise RuntimeError("Proton SRP multiplier is out of bounds")

    password_exp = pow(generator, hashed_password_int, modulus_int)
    base = (server_int - (password_exp * multiplier)) % modulus_int
    exponent = (scramble * hashed_password_int + client_secret) % modulus_minus_one
    shared_secret = _from_le_int(pow(base, exponent, modulus_int), length)
    client_proof = _expand_hash(client_ephemeral + server_ephemeral + shared_secret)
    expected_server_proof = _expand_hash(client_ephemeral + client_proof + shared_secret)

    return {
        "client_ephemeral": base64.b64encode(client_ephemeral).decode("ascii"),
        "client_proof": base64.b64encode(client_proof).decode("ascii"),
        "expected_server_proof": base64.b64encode(expected_server_proof).decode("ascii"),
    }


def _requires_2fa(auth_response):
    twofa = auth_response.get("2FA")
    if isinstance(twofa, dict):
        return bool(twofa.get("Enabled") or twofa.get("TOTP"))
    return bool(auth_response.get("TwoFactor") or auth_response.get("2FARequired"))


def _login_with_password(base_url, username, password, twofa_code=None, app_version=None):
    session = _make_session(base_url, app_version)
    auth_info = _request_json(
        session, "POST", "/auth/info", json={"Username": username}
    )
    version = int(auth_info.get("Version", 4))
    srp_session = auth_info.get("SRPSession")
    if not srp_session:
        raise ProtonAPIError("Proton auth info did not include an SRP session")

    proofs = _generate_srp_proofs(
        version,
        username,
        password,
        auth_info.get("Salt", ""),
        auth_info.get("Modulus", ""),
        auth_info.get("ServerEphemeral", ""),
    )
    auth_response = _request_json(
        session,
        "POST",
        "/auth",
        json={
            "Username": username,
            "ClientEphemeral": proofs["client_ephemeral"],
            "ClientProof": proofs["client_proof"],
            "SRPSession": srp_session,
        },
    )

    server_proof = auth_response.get("ServerProof")
    if server_proof and server_proof != proofs["expected_server_proof"]:
        raise ProtonAPIError("Proton SRP server proof mismatch")

    uid = auth_response.get("UID")
    access_token = auth_response.get("AccessToken")
    if not uid or not access_token:
        raise ProtonAPIError("Proton auth response did not include a session token")

    _apply_bearer_auth(session, uid, access_token)

    if _requires_2fa(auth_response):
        if not twofa_code:
            raise RuntimeError("2FA code is required for this Proton account")
        twofa_response = _request_json(
            session,
            "POST",
            "/auth/2fa",
            json={"TwoFactorCode": twofa_code},
        )
        if isinstance(twofa_response, dict):
            for key in ("UID", "AccessToken", "RefreshToken"):
                if twofa_response.get(key):
                    auth_response[key] = twofa_response[key]

    session.proton_auth = _auth_from_response(
        auth_response,
        session,
        username=username,
    )

    return session


def _extract_uid_from_cookie(cookie_header):
    if not cookie_header:
        return ""
    match = re.search(r"(?:^|;\s*)AUTH-([^=;\s]+)=", cookie_header)
    return match.group(1) if match else ""


def _login_with_session_tokens(base_url, data):
    app_version = data.get("app_version") or PROTON_DEFAULT_APP_VERSION
    session = _make_session(base_url, app_version)

    cookie_header = (data.get("cookie_header") or "").strip()
    auth_uid = (data.get("auth_uid") or "").strip() or _extract_uid_from_cookie(cookie_header)
    auth_token = (data.get("auth_token") or "").strip()
    access_token = (data.get("access_token") or "").strip()
    session_id = (data.get("session_id") or "").strip()

    if cookie_header:
        session.headers["Cookie"] = cookie_header
    if auth_uid:
        session.headers["x-pm-uid"] = auth_uid
    if access_token:
        session.headers["Authorization"] = f"Bearer {access_token}"
    if auth_uid and auth_token:
        session.cookies.set(f"AUTH-{auth_uid}", auth_token)
    if session_id:
        session.cookies.set("Session-Id", session_id)

    if not cookie_header and not access_token and not (auth_uid and auth_token):
        raise RuntimeError(
            "Proton session mode requires either a raw Cookie header, an "
            "AccessToken, or auth_uid + auth_token."
        )

    return session


def _generate_proton_wireguard_keys():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except Exception as exc:
        raise RuntimeError(
            "Proton WireGuard key generation requires the cryptography "
            "Python package. Run pip install -r requirements.txt."
        ) from exc

    private_key = ed25519.Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    digest = bytearray(hashlib.sha512(seed).digest()[:32])
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64

    client_public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    wireguard_private_key = base64.b64encode(bytes(digest)).decode("ascii")
    return wireguard_private_key, client_public_key


def _fetch_vpn_json(session, method, path, **kwargs):
    return _request_json(session, method, path, **kwargs)


def _wireguard_ports_from_client_config(client_config):
    try:
        ports = client_config["DefaultPorts"]["WireGuard"].get("UDP") or []
    except Exception:
        ports = []
    return [int(port) for port in ports if port] or list(PROTON_DEFAULT_WG_PORTS)


def _is_api_enabled(value):
    return value is True or value == 1


def _first_enabled_physical_dict(logical):
    physicals = logical.get("Servers") or logical.get("PhysicalServers") or []
    enabled = [
        item for item in physicals
        if _is_api_enabled(item.get("Status")) and item.get("EntryIP") and item.get("X25519PublicKey")
    ]
    if not enabled:
        return None
    return sorted(
        enabled,
        key=lambda item: (
            item.get("ID") or "",
            item.get("Domain") or "",
            item.get("EntryIP") or "",
        )
    )[0]


def _nodes_from_api_data(logicals_data, private_key, user_tier, wg_port):
    logicals = logicals_data.get("LogicalServers", [])
    nodes = []

    for logical in logicals:
        try:
            tier = int(logical.get("Tier") or 0)
        except (TypeError, ValueError):
            tier = 0
        if not _is_api_enabled(logical.get("Status")) or tier > user_tier:
            continue

        physical = _first_enabled_physical_dict(logical)
        if not physical:
            continue

        feature_names = _feature_names_from_bitmap(logical.get("Features"))
        has_ipv6 = "ipv6" in feature_names
        logical_name = logical.get("Name") or physical.get("Domain") or physical.get("EntryIP")
        proxy = {
            "name": f"Proton {logical_name}",
            "type": "wireguard",
            "server": physical["EntryIP"],
            "port": wg_port,
            "private-key": private_key,
            "public-key": physical["X25519PublicKey"],
            "ip": PROTON_WG_IPV4,
            "allowed-ips": ["0.0.0.0/0", "::/0"],
            "dns": [PROTON_WG_IPV4_DNS],
            "remote-dns-resolve": True,
            "udp": True,
            "mtu": PROTON_WG_MTU,
        }
        if has_ipv6:
            proxy["ipv6"] = PROTON_WG_IPV6
            proxy["dns"] = [PROTON_WG_IPV4_DNS, PROTON_WG_IPV6_DNS]

        node = source_providers.proxy_to_node(proxy, "protonvpn")
        node["metadata"].update({
            "logical_id": logical.get("ID"),
            "server_name": logical.get("Name"),
            "entry_country": logical.get("EntryCountry"),
            "exit_country": logical.get("ExitCountry"),
            "city": logical.get("City"),
            "state": logical.get("State"),
            "load": logical.get("Load"),
            "score": logical.get("Score"),
            "features": feature_names,
            "physical_id": physical.get("ID"),
            "domain": physical.get("Domain"),
            "exit_ip": physical.get("ExitIP"),
            "tier": tier,
        })
        nodes.append(node)

    return nodes


def _fetch_nodes_with_session(session):
    vpn_info = _fetch_vpn_json(session, "GET", "/vpn/v2")
    try:
        user_tier = int(vpn_info.get("VPN", {}).get("MaxTier") or 0)
    except (TypeError, ValueError):
        user_tier = 0

    private_key, client_public_key = _generate_proton_wireguard_keys()
    _fetch_vpn_json(
        session,
        "POST",
        "/vpn/v1/certificate",
        json={
            "ClientPublicKey": client_public_key,
            "Duration": "10080 min",
        },
    )

    try:
        client_config = _fetch_vpn_json(session, "GET", "/vpn/v2/clientconfig")
    except Exception:
        client_config = {}
    wg_port = _wireguard_ports_from_client_config(client_config)[0]
    logicals_data = _fetch_vpn_json(
        session,
        "GET",
        "/vpn/v1/logicals?SecureCoreFilter=all&WithState=true",
    )
    return _nodes_from_api_data(logicals_data, private_key, user_tier, wg_port)


def _fetch_nodes_with_builtin_api(data, source_name="ProtonVPN"):
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    twofa_code = (data.get("twofa_code") or "").strip() or None
    requested_app_version = data.get("app_version")
    app_version = requested_app_version or PROTON_DEFAULT_APP_VERSION
    use_password = bool(username and password)
    use_session = _has_explicit_session_credentials(data)
    stored_auth = _stored_auth_from_data(data)
    auth_base_url = _auth_value(stored_auth, "api_base_url", "base_url") if stored_auth else ""

    base_urls = []
    for base_url in [data.get("api_base_url"), auth_base_url, *PROTON_API_BASE_URLS]:
        if base_url and base_url not in base_urls:
            base_urls.append(base_url)

    last_error = None
    for base_url in base_urls:
        try:
            if use_password:
                session = _login_with_password(base_url, username, password, twofa_code, app_version)
            elif use_session:
                session = _login_with_session_tokens(base_url, data)
            elif stored_auth:
                session = _login_with_saved_auth(base_url, stored_auth, requested_app_version)
            else:
                raise RuntimeError(
                    "Proton fetch requires username/password, session tokens, "
                    "or a previously saved Proton refresh session."
                )
            nodes = _fetch_nodes_with_session(session)
            return nodes, getattr(session, "proton_auth", None)
        except Exception as exc:
            last_error = exc

    if use_password:
        mode = "username/password"
    elif use_session:
        mode = "session-cookie"
    elif stored_auth:
        mode = "saved-session"
    else:
        mode = "credentials"
    raise RuntimeError(f"Built-in Proton {mode} fetch failed: {last_error}") from last_error


def _load_online_nodes(data, source_name="ProtonVPN"):
    nodes, _auth = _fetch_nodes_with_builtin_api(data, source_name)
    return nodes


def load_nodes(content, source_name="ProtonVPN"):
    data = _load_content_config(content)

    nodes = _load_compact_servers(data)
    if nodes:
        return nodes

    nodes = _load_wireguard_configs(data, source_name)
    if nodes:
        return nodes

    return _load_online_nodes(data, source_name)


def fetch_content(
    username=None,
    password=None,
    twofa_code=None,
    source_name="ProtonVPN",
    **kwargs,
):
    data = {
        "username": username or "",
        "password": password or "",
    }
    if twofa_code:
        data["twofa_code"] = twofa_code
    data.update({
        key: value
        for key, value in kwargs.items()
        if value is not None and value != ""
    })

    existing_auth = _stored_auth_from_data(data)
    if existing_auth and not data.get("username"):
        data["username"] = _auth_value(existing_auth, "username")

    nodes, auth = _fetch_nodes_with_builtin_api(data, source_name)
    nodes, stats = _apply_proton_node_filters(nodes, data)
    effective_username = username or data.get("username") or _auth_value(auth, "username")
    return _serialize_nodes_to_content(
        nodes,
        effective_username or "",
        auth,
        stats=stats,
        filters=_proton_filter_config(data),
    ), nodes
