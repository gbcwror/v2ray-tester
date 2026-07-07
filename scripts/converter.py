# scripts/converter.py
"""
Xray Share Link <-> JSON Converter
Supports: vless://, vmess://, ss://, trojan://, hy2://, hysteria2://, wireguard://, wg://
"""

import json
import base64
from urllib.parse import urlparse, parse_qs, unquote


def b64decode_safe(data: str) -> bytes:
    data = data.strip()
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data)
    except Exception:
        return base64.urlsafe_b64decode(data)


def parse_port(port) -> int:
    if port is None:
        raise ValueError("Missing port in URL")
    port = int(port)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")
    return port


def _split_host_port(server_part: str) -> tuple:
    server_part = server_part.strip()
    if server_part.startswith("["):
        bracket_end = server_part.index("]")
        host = server_part[1:bracket_end]
        rest = server_part[bracket_end + 1:]
        if not rest.startswith(":"):
            raise ValueError(f"Invalid IPv6 address/port: {server_part!r}")
        port_str = rest[1:]
    else:
        if ":" not in server_part:
            raise ValueError(f"Missing port in server address: {server_part!r}")
        host, port_str = server_part.rsplit(":", 1)

    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Invalid port number: {port_str!r}")

    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")

    return host, port


def build_transport_settings(network: str, params: dict) -> dict:
    settings_key = None
    transport = {}

    if network in ("ws", "websocket"):
        settings_key = "wsSettings"
        if "path" in params:
            transport["path"] = unquote(params["path"][0])
        if "host" in params:
            transport["host"] = params["host"][0]

    elif network == "grpc":
        settings_key = "grpcSettings"
        if "serviceName" in params:
            transport["serviceName"] = params["serviceName"][0]
        if "authority" in params:
            transport["authority"] = params["authority"][0]
        if "mode" in params and params["mode"][0] == "multi":
            transport["multiMode"] = True

    elif network == "httpupgrade":
        settings_key = "httpupgradeSettings"
        if "path" in params:
            transport["path"] = unquote(params["path"][0])
        if "host" in params:
            transport["host"] = params["host"][0]

    elif network in ("xhttp", "splithttp"):
        settings_key = "xhttpSettings"
        if "path" in params:
            transport["path"] = unquote(params["path"][0])
        if "host" in params:
            transport["host"] = params["host"][0]
        if "mode" in params:
            transport["mode"] = params["mode"][0]
        if "extra" in params:
            try:
                transport["extra"] = json.loads(unquote(params["extra"][0]))
            except (json.JSONDecodeError, Exception):
                pass

    elif network in ("tcp", "raw"):
        header_type = params.get("headerType", ["none"])[0]
        if header_type == "http":
            settings_key = "tcpSettings"
            transport["header"] = {"type": "http"}
            if "host" in params:
                hosts = params["host"][0].split(",")
                transport["header"]["request"] = {
                    "headers": {"Host": hosts}
                }

    elif network in ("kcp", "mkcp"):
        settings_key = "kcpSettings"

    if settings_key and transport:
        return {settings_key: transport}
    return {}


def build_security_settings(security: str, params: dict) -> dict:
    result = {}

    if security == "tls":
        tls = {}
        if "sni" in params:
            tls["serverName"] = params["sni"][0]
        if "fp" in params:
            tls["fingerprint"] = params["fp"][0]
        if "alpn" in params:
            tls["alpn"] = params["alpn"][0].split(",")
        if "pcs" in params:
            tls["pinnedPeerCertSha256"] = params["pcs"][0]
        if "vcn" in params:
            tls["verifyPeerCertByName"] = params["vcn"][0]
        if tls:
            result["tlsSettings"] = tls

    elif security == "reality":
        reality = {}
        if "sni" in params:
            reality["serverName"] = params["sni"][0]
        if "fp" in params:
            reality["fingerprint"] = params["fp"][0]
        if "pbk" in params:
            reality["publicKey"] = params["pbk"][0]
        if "sid" in params:
            reality["shortId"] = params["sid"][0]
        if "spx" in params:
            reality["spiderX"] = unquote(params["spx"][0])
        if reality:
            result["realitySettings"] = reality

    return result


def build_stream_settings(params: dict) -> dict:
    network = params.get("type", ["tcp"])[0]
    security = params.get("security", ["none"])[0]

    stream = {"network": network, "security": security}
    stream.update(build_security_settings(security, params))
    stream.update(build_transport_settings(network, params))

    return stream


def parse_vless(link: str):
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    remark = unquote(parsed.fragment) if parsed.fragment else ""

    port = parse_port(parsed.port)

    user = {
        "id": parsed.username,
        "encryption": params.get("encryption", ["none"])[0],
    }
    flow = params.get("flow", [""])[0]
    if flow:
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "tag": "proxy",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": port,
                "users": [user],
            }]
        },
        "streamSettings": build_stream_settings(params),
    }

    return outbound, remark


def parse_vmess(link: str):
    raw = link[len("vmess://"):]
    decoded = json.loads(b64decode_safe(raw).decode("utf-8"))

    net = decoded.get("net", "tcp")
    tls_val = decoded.get("tls", "")
    security = tls_val if tls_val else "none"
    remark = decoded.get("ps", "")

    params = {"type": [net], "security": [security]}

    if decoded.get("sni"):
        params["sni"] = [decoded["sni"]]
    if decoded.get("fp"):
        params["fp"] = [decoded["fp"]]
    if decoded.get("alpn"):
        params["alpn"] = [decoded["alpn"]]

    if net in ("ws", "websocket", "httpupgrade"):
        if decoded.get("host"):
            params["host"] = [decoded["host"]]
        if decoded.get("path"):
            params["path"] = [decoded["path"]]

    elif net == "grpc":
        if decoded.get("path"):
            params["serviceName"] = [decoded["path"]]
        if decoded.get("host"):
            params["authority"] = [decoded["host"]]
        if decoded.get("type") == "multi":
            params["mode"] = ["multi"]

    elif net in ("xhttp", "splithttp"):
        if decoded.get("host"):
            params["host"] = [decoded["host"]]
        if decoded.get("path"):
            params["path"] = [decoded["path"]]
        if decoded.get("mode"):
            params["mode"] = [decoded["mode"]]

    elif net in ("tcp", "raw"):
        header_type = decoded.get("type", "none")
        if header_type and header_type != "none":
            params["headerType"] = [header_type]
        if decoded.get("host"):
            params["host"] = [decoded["host"]]

    scy = decoded.get("scy", decoded.get("security", "auto"))
    if not scy:
        scy = "auto"

    port = decoded.get("port", 0)
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid VMess port: {port!r}")
    if port == 0:
        raise ValueError("Missing or zero port in VMess link")

    outbound = {
        "protocol": "vmess",
        "tag": "proxy",
        "settings": {
            "vnext": [{
                "address": decoded.get("add", ""),
                "port": port,
                "users": [{
                    "id": decoded.get("id", ""),
                    "security": scy,
                }],
            }]
        },
        "streamSettings": build_stream_settings(params),
    }

    return outbound, remark


def parse_ss(link: str):
    raw = link[len("ss://"):]

    fragment = ""
    if "#" in raw:
        raw, fragment = raw.rsplit("#", 1)
        fragment = unquote(fragment)

    if "?" in raw:
        raw = raw.split("?", 1)[0]

    if "@" in raw:
        userinfo_part, server_part = raw.rsplit("@", 1)
        try:
            userinfo = b64decode_safe(userinfo_part).decode("utf-8")
        except Exception:
            userinfo = unquote(userinfo_part)

        if ":" not in userinfo:
            raise ValueError("Invalid SS userinfo: missing colon separator")
        method, password = userinfo.split(":", 1)

        host, port = _split_host_port(server_part)

    else:
        decoded_str = b64decode_safe(raw).decode("utf-8")
        if "@" not in decoded_str:
            raise ValueError("Invalid legacy SS link: missing '@'")
        method_pass, server_part = decoded_str.rsplit("@", 1)
        if ":" not in method_pass:
            raise ValueError("Invalid legacy SS link: missing ':' in userinfo")
        method, password = method_pass.split(":", 1)
        host, port = _split_host_port(server_part)

    outbound = {
        "protocol": "shadowsocks",
        "tag": "proxy",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
            }]
        },
        "streamSettings": {"network": "tcp", "security": "none"},
    }

    return outbound, fragment


def parse_trojan(link: str):
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    remark = unquote(parsed.fragment) if parsed.fragment else ""

    port = parse_port(parsed.port)

    if "security" not in params:
        params["security"] = ["tls"]

    outbound = {
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "servers": [{
                "address": parsed.hostname,
                "port": port,
                "password": unquote(parsed.username),
            }]
        },
        "streamSettings": build_stream_settings(params),
    }

    return outbound, remark


def parse_hysteria2(link: str):
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    remark = unquote(parsed.fragment) if parsed.fragment else ""

    port = parse_port(parsed.port)
    auth = unquote(parsed.username) if parsed.username else ""

    tls = {}
    sni = params.get("sni", [""])[0]
    if sni:
        tls["serverName"] = sni
    if "fingerprint" in params:
        tls["fingerprint"] = params["fingerprint"][0]
    elif "fp" in params:
        tls["fingerprint"] = params["fp"][0]
    if "alpn" in params:
        tls["alpn"] = params["alpn"][0].split(",")
    if "pcs" in params:
        tls["pinnedPeerCertSha256"] = params["pcs"][0]
    if "vcn" in params:
        tls["verifyPeerCertByName"] = params["vcn"][0]

    stream = {
        "network": "hysteria",
        "security": "tls",
        "hysteriaSettings": {
            "version": 2,
            "auth": auth,
        },
    }

    if tls:
        stream["tlsSettings"] = tls

    obfs = params.get("obfs", [""])[0]
    obfs_password = params.get("obfs-password", [""])[0]
    if obfs and obfs_password:
        stream["hysteriaSettings"]["obfs"] = obfs
        stream["hysteriaSettings"]["obfsPassword"] = obfs_password

    outbound = {
        "protocol": "hysteria2",
        "tag": "proxy",
        "settings": {
            "version": 2,
            "address": parsed.hostname,
            "port": port,
        },
        "streamSettings": stream,
    }

    return outbound, remark


def parse_wireguard(link: str):
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    remark = unquote(parsed.fragment) if parsed.fragment else ""

    port = parse_port(parsed.port)
    secret_key = unquote(parsed.username) if parsed.username else ""

    if not secret_key:
        raise ValueError("WireGuard: missing private/secret key")

    public_key = params.get("publickey", params.get("publicKey", [""]))[0]
    if not public_key:
        raise ValueError("WireGuard: missing peer public key")

    addresses = params.get("address", [])
    if not addresses:
        addresses = ["10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"]

    reserved = []
    reserved_str = params.get("reserved", [""])[0]
    if reserved_str:
        try:
            reserved = [int(x) for x in reserved_str.split(",")]
        except ValueError:
            raise ValueError(f"WireGuard: invalid reserved value: {reserved_str!r}")
        if len(reserved) != 3:
            raise ValueError("WireGuard: reserved must be exactly 3 bytes")

    mtu = 1420
    mtu_str = params.get("mtu", [""])[0]
    if mtu_str:
        try:
            mtu = int(mtu_str)
        except ValueError:
            raise ValueError(f"WireGuard: invalid MTU: {mtu_str!r}")

    endpoint = f"{parsed.hostname}:{port}"

    peer = {
        "publicKey": public_key,
        "endpoint": endpoint,
        "allowedIPs": ["0.0.0.0/0", "::0/0"],
    }

    psk = params.get("presharedkey", params.get("preSharedKey", [""]))[0]
    if psk:
        peer["preSharedKey"] = psk

    keepalive_str = params.get("keepalive", params.get("keepAlive", [""]))[0]
    if keepalive_str:
        try:
            peer["keepAlive"] = int(keepalive_str)
        except ValueError:
            pass

    settings = {
        "secretKey": secret_key,
        "address": addresses,
        "peers": [peer],
        "mtu": mtu,
    }

    if reserved:
        settings["reserved"] = reserved

    outbound = {
        "protocol": "wireguard",
        "tag": "proxy",
        "settings": settings,
    }

    return outbound, remark


def convert_link(link: str):
    """Returns (outbound_dict, remark_string)."""
    link = link.strip()
    if not link:
        raise ValueError("Empty link")

    if link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("ss://"):
        return parse_ss(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    elif link.startswith("hy2://") or link.startswith("hysteria2://"):
        return parse_hysteria2(link)
    elif link.startswith("wireguard://") or link.startswith("wg://"):
        return parse_wireguard(link)
    else:
        scheme = link.split("://")[0] if "://" in link else "unknown"
        raise ValueError(f"Unsupported protocol: {scheme}")


def get_protocol(link: str) -> str:
    """Extract protocol name from share link."""
    link = link.strip()
    if link.startswith("vless://"):
        return "vless"
    elif link.startswith("vmess://"):
        return "vmess"
    elif link.startswith("ss://"):
        return "ss"
    elif link.startswith("trojan://"):
        return "trojan"
    elif link.startswith("hy2://") or link.startswith("hysteria2://"):
        return "hysteria2"
    elif link.startswith("wireguard://") or link.startswith("wg://"):
        return "wireguard"
    return "unknown"


def build_xray_config(outbound: dict, socks_port: int) -> dict:
    """Build minimal Xray config for testing."""
    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "settings": {
                "auth": "noauth",
                "udp": True,
            },
        }],
        "outbounds": [
            outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
            },
        ],
    }