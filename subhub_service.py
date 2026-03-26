from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import aiohttp
import yaml


DEFAULT_FETCH_TIMEOUT = 15
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return fallback


def _split_csv(value: str) -> list[str]:
    items: list[str] = []
    for chunk in str(value or "").replace("|", ",").split(","):
        piece = chunk.strip()
        if piece:
            items.append(piece)
    return items


def _is_true(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _cleanup_name(name: str, fallback: str) -> str:
    raw = str(name or "").strip()
    if not raw:
        raw = fallback
    return raw.replace("\n", " ").replace("\r", " ").strip()[:80]


def _decode_url_b64(text: str) -> str:
    compact = "".join(str(text or "").strip().split())
    if not compact:
        return ""
    if not set(compact).issubset(BASE64_CHARS):
        return ""
    pad = "=" * ((4 - len(compact) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            data = decoder((compact + pad).encode("utf-8"))
            decoded = data.decode("utf-8", errors="ignore").strip()
            if decoded:
                return decoded
        except Exception:
            continue
    return ""


def _extract_links(text: str) -> list[str]:
    raw = str(text or "").strip()
    if not raw:
        return []

    def _collect_links(payload: str) -> list[str]:
        lines: list[str] = []
        for row in payload.replace("\r", "\n").split("\n"):
            row = row.strip()
            if not row:
                continue
            for token in row.split():
                token = token.strip()
                if "://" in token:
                    lines.append(token)
        return lines

    direct_links = _collect_links(raw)
    decoded_links: list[str] = []
    decoded = _decode_url_b64(raw)
    if decoded:
        decoded_links = _collect_links(decoded)

    links = decoded_links if len(decoded_links) >= len(direct_links) else direct_links

    unique: list[str] = []
    seen: set[str] = set()
    for item in links:
        norm = item.strip()
        if not norm or "://" not in norm:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        unique.append(norm)
    return unique


def _parse_host_port(hostport: str) -> tuple[str, int] | None:
    probe = urlsplit(f"//{hostport}")
    if not probe.hostname or not probe.port:
        return None
    return probe.hostname, int(probe.port)


def _sanitize_link_for_nekobox(link: str) -> str:
    return str(link or "").strip()


def _to_query_map(link: str) -> dict[str, str]:
    query = parse_qs(urlsplit(link).query, keep_blank_values=True)
    return {k: str(v[-1]) for k, v in query.items() if v}


def _parse_vmess(link: str) -> dict[str, Any] | None:
    payload = link[len("vmess://") :]
    decoded = _decode_url_b64(payload)
    if not decoded:
        return None
    try:
        obj = json.loads(decoded)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None

    server = str(obj.get("add") or "").strip()
    port = _safe_int(obj.get("port"), 0)
    uuid = str(obj.get("id") or "").strip()
    if not server or port <= 0 or not uuid:
        return None

    network = str(obj.get("net") or "tcp").strip().lower() or "tcp"
    tls_mode = str(obj.get("tls") or "").strip().lower()
    security = "tls" if tls_mode in {"tls", "reality"} else "none"

    return {
        "type": "vmess",
        "name": _cleanup_name(unquote(str(obj.get("ps") or "")), f"vmess-{server}:{port}"),
        "server": server,
        "port": port,
        "uuid": uuid,
        "aid": _safe_int(obj.get("aid"), 0),
        "cipher": str(obj.get("scy") or "auto").strip() or "auto",
        "network": network,
        "host": str(obj.get("host") or "").strip(),
        "path": str(obj.get("path") or "").strip(),
        "security": security,
        "sni": str(obj.get("sni") or "").strip(),
        "alpn": _split_csv(str(obj.get("alpn") or "")),
        "fp": str(obj.get("fp") or "").strip(),
        "insecure": _is_true(obj.get("allowInsecure")),
        "service_name": str(obj.get("serviceName") or obj.get("service_name") or "").strip(),
    }


def _parse_vless_or_trojan(link: str, proto: str) -> dict[str, Any] | None:
    parsed = urlsplit(link)
    host = parsed.hostname or ""
    port = parsed.port or 0
    if not host or port <= 0:
        return None
    q = _to_query_map(link)

    if proto == "vless":
        uuid = unquote(parsed.username or "").strip()
        if not uuid:
            return None
        fallback_name = f"vless-{host}:{port}"
        security = str(q.get("security") or "none").strip().lower() or "none"
        encryption = str(q.get("encryption") or "").strip()
        flow = str(q.get("flow") or "").strip()
        return {
            "type": "vless",
            "name": _cleanup_name(unquote(parsed.fragment or ""), fallback_name),
            "server": host,
            "port": int(port),
            "uuid": uuid,
            "network": str(q.get("type") or "tcp").strip().lower() or "tcp",
            "security": security,
            "sni": str(q.get("sni") or q.get("servername") or q.get("host") or "").strip(),
            "host": str(q.get("host") or "").strip(),
            "path": str(q.get("path") or "").strip(),
            "service_name": str(q.get("serviceName") or q.get("service_name") or "").strip(),
            "alpn": _split_csv(str(q.get("alpn") or "")),
            "flow": flow,
            "encryption": encryption,
            "fp": str(q.get("fp") or "").strip(),
            "pbk": str(q.get("pbk") or q.get("publicKey") or "").strip(),
            "sid": str(q.get("sid") or q.get("short_id") or "").strip(),
            "spx": str(q.get("spx") or q.get("spiderX") or "").strip(),
            "insecure": _is_true(q.get("allowInsecure") or q.get("insecure")),
        }

    password = unquote(parsed.username or "").strip()
    if not password:
        return None
    security = str(q.get("security") or "tls").strip().lower() or "tls"
    return {
        "type": "trojan",
        "name": _cleanup_name(unquote(parsed.fragment or ""), f"trojan-{host}:{port}"),
        "server": host,
        "port": int(port),
        "password": password,
        "network": str(q.get("type") or "tcp").strip().lower() or "tcp",
        "security": security,
        "sni": str(q.get("sni") or q.get("servername") or q.get("host") or "").strip(),
        "host": str(q.get("host") or "").strip(),
        "path": str(q.get("path") or "").strip(),
        "service_name": str(q.get("serviceName") or q.get("service_name") or "").strip(),
        "alpn": _split_csv(str(q.get("alpn") or "")),
        "fp": str(q.get("fp") or "").strip(),
        "insecure": _is_true(q.get("allowInsecure") or q.get("insecure")),
    }


def _parse_ss(link: str) -> dict[str, Any] | None:
    raw = link[len("ss://") :]
    if not raw:
        return None

    if "#" in raw:
        raw, frag = raw.split("#", 1)
        name = unquote(frag)
    else:
        name = ""

    if "?" in raw:
        raw, _ = raw.split("?", 1)

    def _parse_ss_userinfo(userinfo: str) -> tuple[str, str] | None:
        text = unquote(str(userinfo or "").strip())
        if not text:
            return None
        if ":" in text:
            method_value, password_value = text.split(":", 1)
            method_value = method_value.strip()
            if not method_value:
                return None
            return method_value, password_value
        decoded = _decode_url_b64(text)
        if not decoded or ":" not in decoded:
            return None
        method_value, password_value = decoded.split(":", 1)
        method_value = method_value.strip()
        if not method_value:
            return None
        return method_value, password_value

    method = ""
    password = ""
    host = ""
    port = 0

    raw = raw.strip().strip("/")

    if "@" in raw:
        # SIP002: method:password@host:port OR base64(method:password)@host:port
        left, right = raw.rsplit("@", 1)
        hp = _parse_host_port(right.strip().strip("/"))
        creds = _parse_ss_userinfo(left)
        if hp and creds:
            host, port = hp
            method, password = creds

    if not host:
        # Legacy: base64(method:password@host:port)
        decoded = _decode_url_b64(raw)
        if not decoded or "@" not in decoded:
            return None
        left, right = decoded.strip().strip("/").rsplit("@", 1)
        hp = _parse_host_port(right.strip().strip("/"))
        creds = _parse_ss_userinfo(left)
        if not hp or not creds:
            return None
        host, port = hp
        method, password = creds

    method = unquote(method).strip()
    password = unquote(password).strip()
    if not host or port <= 0 or not method:
        return None

    return {
        "type": "ss",
        "name": _cleanup_name(name, f"ss-{host}:{port}"),
        "server": host,
        "port": int(port),
        "method": method,
        "password": password,
    }


def _parse_node(link: str) -> dict[str, Any] | None:
    if link.startswith("vmess://"):
        return _parse_vmess(link)
    if link.startswith("vless://"):
        return _parse_vless_or_trojan(link, "vless")
    if link.startswith("trojan://"):
        return _parse_vless_or_trojan(link, "trojan")
    if link.startswith("ss://"):
        return _parse_ss(link)
    return None


def _format_host_for_uri(host: str) -> str:
    text = str(host or "").strip()
    if ":" in text and not text.startswith("["):
        return f"[{text}]"
    return text


def _pack_b64(text: str, *, strip_padding: bool = False) -> str:
    raw = base64.b64encode(str(text or "").encode("utf-8")).decode("ascii")
    return raw.rstrip("=") if strip_padding else raw


def _build_share_link(node: dict[str, Any], *, nekobox_compat: bool = False) -> str | None:
    proto = str(node.get("type") or "").strip().lower()
    server = str(node.get("server") or "").strip()
    port = _safe_int(node.get("port"), 0)
    if not proto or not server or port <= 0:
        return None

    display_name = _cleanup_name(str(node.get("name") or "").strip(), f"{proto}-{server}:{port}")
    host = _format_host_for_uri(server)

    if proto == "vmess":
        vmess_obj: dict[str, Any] = {
            "v": "2",
            "ps": display_name,
            "add": server,
            "port": str(port),
            "id": str(node.get("uuid") or ""),
            "aid": str(_safe_int(node.get("aid"), 0)),
            "scy": str(node.get("cipher") or "auto"),
            "net": str(node.get("network") or "tcp"),
            "type": "none",
            "host": str(node.get("host") or ""),
            "path": str(node.get("path") or ""),
        }
        security = str(node.get("security") or "none").strip().lower()
        if security in {"tls", "reality"}:
            vmess_obj["tls"] = security
        sni = str(node.get("sni") or "").strip()
        if sni:
            vmess_obj["sni"] = sni
        alpn = [str(x).strip() for x in (node.get("alpn") or []) if str(x).strip()]
        if alpn:
            vmess_obj["alpn"] = ",".join(alpn)
        fp = str(node.get("fp") or "").strip()
        if fp:
            vmess_obj["fp"] = fp
        service_name = str(node.get("service_name") or "").strip()
        if service_name:
            vmess_obj["serviceName"] = service_name
        if _is_true(node.get("insecure")):
            vmess_obj["allowInsecure"] = 1
        payload = json.dumps(vmess_obj, ensure_ascii=False, separators=(",", ":"))
        return f"vmess://{_pack_b64(payload)}"

    if proto == "vless":
        uuid = str(node.get("uuid") or "").strip()
        if not uuid:
            return None
        params: list[tuple[str, str]] = []
        network = str(node.get("network") or "tcp").strip().lower()
        if network:
            params.append(("type", network))
        encryption = str(node.get("encryption") or "").strip()
        if encryption:
            params.append(("encryption", encryption))
        flow = str(node.get("flow") or "").strip()
        if not flow and nekobox_compat and encryption and encryption.lower() not in {"none", "auto"}:
            flow = encryption
        if flow and (nekobox_compat or flow.lower().startswith("xtls-rprx-")):
            params.append(("flow", flow))
        security = str(node.get("security") or "").strip().lower()
        if security and security != "none":
            params.append(("security", security))
        sni = str(node.get("sni") or "").strip()
        if sni:
            params.append(("sni", sni))
        host_header = str(node.get("host") or "").strip()
        if host_header:
            params.append(("host", host_header))
        path = str(node.get("path") or "").strip()
        if path:
            params.append(("path", path))
        service_name = str(node.get("service_name") or "").strip()
        if service_name:
            params.append(("serviceName", service_name))
        alpn = [str(x).strip() for x in (node.get("alpn") or []) if str(x).strip()]
        if alpn:
            params.append(("alpn", ",".join(alpn)))
        fp = str(node.get("fp") or "").strip()
        if fp:
            params.append(("fp", fp))
        pbk = str(node.get("pbk") or "").strip()
        if pbk:
            params.append(("pbk", pbk))
        sid = str(node.get("sid") or "").strip()
        if sid:
            params.append(("sid", sid))
        spx = str(node.get("spx") or "").strip()
        if spx:
            params.append(("spx", spx))
        if _is_true(node.get("insecure")):
            params.append(("allowInsecure", "1"))
        query = urlencode(params)
        base = f"vless://{quote(uuid, safe='')}@{host}:{port}"
        if query:
            base += f"?{query}"
        return f"{base}#{quote(display_name, safe='')}"

    if proto == "trojan":
        password = str(node.get("password") or "").strip()
        if not password:
            return None
        params: list[tuple[str, str]] = []
        network = str(node.get("network") or "tcp").strip().lower()
        if network:
            params.append(("type", network))
        security = str(node.get("security") or "tls").strip().lower() or "tls"
        if security:
            params.append(("security", security))
        sni = str(node.get("sni") or "").strip()
        if sni:
            params.append(("sni", sni))
        host_header = str(node.get("host") or "").strip()
        if host_header:
            params.append(("host", host_header))
        path = str(node.get("path") or "").strip()
        if path:
            params.append(("path", path))
        service_name = str(node.get("service_name") or "").strip()
        if service_name:
            params.append(("serviceName", service_name))
        alpn = [str(x).strip() for x in (node.get("alpn") or []) if str(x).strip()]
        if alpn:
            params.append(("alpn", ",".join(alpn)))
        fp = str(node.get("fp") or "").strip()
        if fp:
            params.append(("fp", fp))
        if _is_true(node.get("insecure")):
            params.append(("allowInsecure", "1"))
        query = urlencode(params)
        base = f"trojan://{quote(password, safe='')}@{host}:{port}"
        if query:
            base += f"?{query}"
        return f"{base}#{quote(display_name, safe='')}"

    if proto == "ss":
        method = str(node.get("method") or "").strip()
        password = str(node.get("password") or "")
        if not method:
            return None
        userinfo = _pack_b64(f"{method}:{password}", strip_padding=True)
        return f"ss://{userinfo}@{host}:{port}#{quote(display_name, safe='')}"

    return None


def _repack_share_links(links: list[str], *, nekobox_compat: bool = False) -> tuple[list[str], int, int]:
    repacked: list[str] = []
    seen: set[str] = set()
    parsed_count = 0
    skipped_count = 0

    for item in links:
        original = str(item or "").strip()
        if not original:
            continue
        node = _parse_node(original)
        if node:
            parsed_count += 1
            rebuilt = _build_share_link(node, nekobox_compat=nekobox_compat) or original
            candidate = rebuilt.strip()
        else:
            skipped_count += 1
            candidate = original
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        repacked.append(candidate)

    return repacked, parsed_count, skipped_count


def _build_transport_clash(node: dict[str, Any], out: dict[str, Any]) -> None:
    network = str(node.get("network") or "tcp").lower()
    if network in {"tcp", "raw"}:
        return
    if network == "ws":
        out["network"] = "ws"
        ws_opts: dict[str, Any] = {}
        path = str(node.get("path") or "").strip()
        host = str(node.get("host") or "").strip()
        if path:
            ws_opts["path"] = path
        if host:
            ws_opts["headers"] = {"Host": host}
        if ws_opts:
            out["ws-opts"] = ws_opts
        return
    if network == "grpc":
        out["network"] = "grpc"
        svc = str(node.get("service_name") or "").strip()
        if svc:
            out["grpc-opts"] = {"grpc-service-name": svc}
        return
    if network in {"http", "h2"}:
        out["network"] = "h2"
        http_opts: dict[str, Any] = {}
        path = str(node.get("path") or "").strip()
        host = str(node.get("host") or "").strip()
        if path:
            http_opts["path"] = [path]
        if host:
            http_opts["host"] = [host]
        if http_opts:
            out["h2-opts"] = http_opts


def _build_tls_clash(node: dict[str, Any], out: dict[str, Any]) -> None:
    security = str(node.get("security") or "none").lower()
    if security not in {"tls", "reality"}:
        return
    out["tls"] = True
    sni = str(node.get("sni") or "").strip()
    if sni:
        out["servername"] = sni
    alpn = node.get("alpn")
    if isinstance(alpn, list) and alpn:
        out["alpn"] = [str(x) for x in alpn if str(x).strip()]
    if _is_true(node.get("insecure")):
        out["skip-cert-verify"] = True
    fp = str(node.get("fp") or "").strip()
    if fp:
        out["client-fingerprint"] = fp

    if security == "reality":
        reality: dict[str, Any] = {}
        pbk = str(node.get("pbk") or "").strip()
        sid = str(node.get("sid") or "").strip()
        spx = str(node.get("spx") or "").strip()
        if pbk:
            reality["public-key"] = pbk
        if sid:
            reality["short-id"] = sid
        if spx:
            reality["spider-x"] = spx
            reality["_spider-x"] = spx
        if reality:
            out["reality-opts"] = reality


def _build_transport_singbox(node: dict[str, Any]) -> dict[str, Any] | None:
    network = str(node.get("network") or "tcp").lower()
    if network in {"tcp", "raw"}:
        return None
    if network == "ws":
        out: dict[str, Any] = {"type": "ws"}
        path = str(node.get("path") or "").strip()
        host = str(node.get("host") or "").strip()
        if path:
            out["path"] = path
        if host:
            out["headers"] = {"Host": host}
        return out
    if network == "grpc":
        out = {"type": "grpc"}
        svc = str(node.get("service_name") or "").strip()
        if svc:
            out["service_name"] = svc
        return out
    if network in {"http", "h2"}:
        out = {"type": "http"}
        path = str(node.get("path") or "").strip()
        host = str(node.get("host") or "").strip()
        if path:
            out["path"] = path
        if host:
            out["host"] = [host]
        return out
    return None


def _build_tls_singbox(node: dict[str, Any]) -> dict[str, Any] | None:
    security = str(node.get("security") or "none").lower()
    if security not in {"tls", "reality"}:
        return None

    tls: dict[str, Any] = {"enabled": True}
    sni = str(node.get("sni") or "").strip()
    if sni:
        tls["server_name"] = sni
    alpn = node.get("alpn")
    if isinstance(alpn, list) and alpn:
        tls["alpn"] = [str(x) for x in alpn if str(x).strip()]
    tls["insecure"] = _is_true(node.get("insecure"))
    fp = str(node.get("fp") or "").strip()
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}

    if security == "reality":
        reality: dict[str, Any] = {"enabled": True}
        pbk = str(node.get("pbk") or "").strip()
        sid = str(node.get("sid") or "").strip()
        if pbk:
            reality["public_key"] = pbk
        if sid:
            reality["short_id"] = sid
        tls["reality"] = reality
    return tls


def _to_clash_proxies(nodes: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    proxies: list[dict[str, Any]] = []
    skipped = 0
    seen_names: set[str] = set()

    for idx, node in enumerate(nodes, start=1):
        base_name = _cleanup_name(str(node.get("name") or "").strip(), f"node-{idx}")
        name = base_name
        suffix = 2
        while name in seen_names:
            name = f"{base_name}-{suffix}"
            suffix += 1
        seen_names.add(name)

        proto = str(node.get("type") or "")
        server = str(node.get("server") or "")
        port = _safe_int(node.get("port"), 0)
        if not proto or not server or port <= 0:
            skipped += 1
            continue

        if proto == "vmess":
            proxy: dict[str, Any] = {
                "name": name,
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": str(node.get("uuid") or ""),
                "alterId": _safe_int(node.get("aid"), 0),
                "cipher": str(node.get("cipher") or "auto"),
                "udp": True,
            }
            _build_transport_clash(node, proxy)
            _build_tls_clash(node, proxy)
            proxies.append(proxy)
            continue

        if proto == "vless":
            proxy = {
                "name": name,
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": str(node.get("uuid") or ""),
                "udp": True,
            }
            encryption = str(node.get("encryption") or "").strip()
            if encryption:
                proxy["encryption"] = encryption
            flow = str(node.get("flow") or "").strip()
            if flow and flow.lower().startswith("xtls-rprx-"):
                proxy["flow"] = flow
            _build_transport_clash(node, proxy)
            _build_tls_clash(node, proxy)
            proxies.append(proxy)
            continue

        if proto == "trojan":
            proxy = {
                "name": name,
                "type": "trojan",
                "server": server,
                "port": port,
                "password": str(node.get("password") or ""),
                "udp": True,
            }
            _build_transport_clash(node, proxy)
            _build_tls_clash(node, proxy)
            proxies.append(proxy)
            continue

        if proto == "ss":
            proxy = {
                "name": name,
                "type": "ss",
                "server": server,
                "port": port,
                "cipher": str(node.get("method") or "aes-128-gcm"),
                "password": str(node.get("password") or ""),
                "udp": True,
            }
            proxies.append(proxy)
            continue

        skipped += 1

    return proxies, skipped


def _to_singbox_outbounds(nodes: list[dict[str, Any]], *, nekobox_compat: bool = False) -> tuple[list[dict[str, Any]], int, list[str]]:
    outbounds: list[dict[str, Any]] = []
    skipped = 0
    tags: list[str] = []
    seen_tags: set[str] = set()

    for idx, node in enumerate(nodes, start=1):
        base_tag = _cleanup_name(str(node.get("name") or "").strip(), f"node-{idx}")
        tag = base_tag
        suffix = 2
        while tag in seen_tags:
            tag = f"{base_tag}-{suffix}"
            suffix += 1
        seen_tags.add(tag)

        proto = str(node.get("type") or "")
        server = str(node.get("server") or "")
        port = _safe_int(node.get("port"), 0)
        if not proto or not server or port <= 0:
            skipped += 1
            continue

        if proto == "vmess":
            outbound: dict[str, Any] = {
                "type": "vmess",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": str(node.get("uuid") or ""),
                "alter_id": _safe_int(node.get("aid"), 0),
                "security": str(node.get("cipher") or "auto"),
            }
        elif proto == "vless":
            outbound = {
                "type": "vless",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": str(node.get("uuid") or ""),
            }
            flow = str(node.get("flow") or "").strip()
            if not flow and nekobox_compat:
                encryption = str(node.get("encryption") or "").strip()
                if encryption and encryption.lower() not in {"none", "auto"}:
                    flow = encryption
            if flow and (nekobox_compat or flow.lower().startswith("xtls-rprx-")):
                outbound["flow"] = flow
            if nekobox_compat:
                packet_encoding = "xudp"
                if str(node.get("network") or "tcp").lower() in {"tcp", "raw"}:
                    packet_encoding = "xudp"
                outbound["packet_encoding"] = packet_encoding
        elif proto == "trojan":
            outbound = {
                "type": "trojan",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": str(node.get("password") or ""),
            }
        elif proto == "ss":
            outbound = {
                "type": "shadowsocks",
                "tag": tag,
                "server": server,
                "server_port": port,
                "method": str(node.get("method") or "aes-128-gcm"),
                "password": str(node.get("password") or ""),
            }
        else:
            skipped += 1
            continue

        tls = _build_tls_singbox(node)
        if tls:
            outbound["tls"] = tls
        transport = _build_transport_singbox(node)
        if transport:
            outbound["transport"] = transport

        outbounds.append(outbound)
        tags.append(tag)

    return outbounds, skipped, tags


def _unique_items(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _build_clash_meta_groups(proxy_names: list[str]) -> list[dict[str, Any]]:
    node_names = _unique_items([str(x) for x in proxy_names if str(x or "").strip()])
    select_base = _unique_items(["⚡ 自动选择", "DIRECT", "REJECT", *node_names])
    auto_nodes = node_names if node_names else ["DIRECT"]

    groups: list[dict[str, Any]] = [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": select_base,
        },
        {
            "name": "⚡ 自动选择",
            "type": "url-test",
            "proxies": auto_nodes,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "lazy": False,
        },
        {
            "name": "🛑 广告拦截",
            "type": "select",
            "proxies": ["REJECT", "DIRECT", "🚀 节点选择"],
        },
    ]

    common_select = _unique_items(["🚀 节点选择", "⚡ 自动选择", "DIRECT", "REJECT", *node_names])
    direct_first = _unique_items(["DIRECT", "REJECT", "🚀 节点选择", "⚡ 自动选择", *node_names])

    category_groups = [
        "🤖 AI 服务",
        "📹 油管视频",
        "🔍 谷歌服务",
        "Ⓜ️ 微软服务",
        "🍏 苹果服务",
        "📲 电报消息",
        "🐦 推特/X",
        "📘 Meta 系",
        "🎙️ Discord",
        "🎬 奈飞",
        "🎮 Steam",
        "🐱 代码托管",
        "☁️ 云服务",
        "🛠️ 开发工具",
        "💾 网盘存储",
        "💳 支付平台",
        "₿ 加密货币",
        "📚 教育学术",
        "📰 新闻资讯",
        "🛒 海淘购物",
        "💬 其他社交",
    ]
    for name in category_groups:
        groups.append({"name": name, "type": "select", "proxies": common_select})

    groups.extend(
        [
            {"name": "🏠 私有网络", "type": "select", "proxies": direct_first},
            {"name": "🔒 国内服务", "type": "select", "proxies": direct_first},
            {"name": "🌍 非中国", "type": "select", "proxies": common_select},
            {"name": "🐟 漏网之鱼", "type": "select", "proxies": common_select},
        ]
    )
    return groups


def _build_clash_meta_rule_providers() -> dict[str, dict[str, Any]]:
    base = "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo"

    def provider(key: str, behavior: str, rel: str) -> dict[str, Any]:
        return {
            "type": "http",
            "behavior": behavior,
            "url": f"{base}/{rel}",
            "path": f"./ruleset/{key}.mrs",
            "interval": 86400,
            "format": "mrs",
        }

    return {
        "category-ads-all": provider("category-ads-all", "domain", "geosite/category-ads-all.mrs"),
        "private": provider("private", "domain", "geosite/private.mrs"),
        "private-ip": provider("private-ip", "ipcidr", "geoip/private.mrs"),
        "geolocation-cn": provider("geolocation-cn", "domain", "geosite/geolocation-cn.mrs"),
        "cn": provider("cn", "domain", "geosite/cn.mrs"),
        "cn-ip": provider("cn-ip", "ipcidr", "geoip/cn.mrs"),
        "geolocation-!cn": provider("geolocation-!cn", "domain", "geosite/geolocation-!cn.mrs"),
        "category-ai-chat-!cn": provider("category-ai-chat-!cn", "domain", "geosite/category-ai-chat-!cn.mrs"),
        "openai": provider("openai", "domain", "geosite/openai.mrs"),
        "anthropic": provider("anthropic", "domain", "geosite/anthropic.mrs"),
        "youtube": provider("youtube", "domain", "geosite/youtube.mrs"),
        "google": provider("google", "domain", "geosite/google.mrs"),
        "google-ip": provider("google-ip", "ipcidr", "geoip/google.mrs"),
        "microsoft": provider("microsoft", "domain", "geosite/microsoft.mrs"),
        "onedrive": provider("onedrive", "domain", "geosite/onedrive.mrs"),
        "apple": provider("apple", "domain", "geosite/apple.mrs"),
        "icloud": provider("icloud", "domain", "geosite/icloud.mrs"),
        "telegram": provider("telegram", "domain", "geosite/telegram.mrs"),
        "telegram-ip": provider("telegram-ip", "ipcidr", "geoip/telegram.mrs"),
        "twitter": provider("twitter", "domain", "geosite/twitter.mrs"),
        "twitter-ip": provider("twitter-ip", "ipcidr", "geoip/twitter.mrs"),
        "facebook": provider("facebook", "domain", "geosite/facebook.mrs"),
        "instagram": provider("instagram", "domain", "geosite/instagram.mrs"),
        "whatsapp": provider("whatsapp", "domain", "geosite/whatsapp.mrs"),
        "facebook-ip": provider("facebook-ip", "ipcidr", "geoip/facebook.mrs"),
        "discord": provider("discord", "domain", "geosite/discord.mrs"),
        "reddit": provider("reddit", "domain", "geosite/reddit.mrs"),
        "linkedin": provider("linkedin", "domain", "geosite/linkedin.mrs"),
        "tiktok": provider("tiktok", "domain", "geosite/tiktok.mrs"),
        "line": provider("line", "domain", "geosite/line.mrs"),
        "netflix": provider("netflix", "domain", "geosite/netflix.mrs"),
        "netflix-ip": provider("netflix-ip", "ipcidr", "geoip/netflix.mrs"),
        "steam": provider("steam", "domain", "geosite/steam.mrs"),
        "github": provider("github", "domain", "geosite/github.mrs"),
        "gitlab": provider("gitlab", "domain", "geosite/gitlab.mrs"),
        "aws": provider("aws", "domain", "geosite/aws.mrs"),
        "azure": provider("azure", "domain", "geosite/azure.mrs"),
        "cloudflare": provider("cloudflare", "domain", "geosite/cloudflare.mrs"),
        "cloudflare-ip": provider("cloudflare-ip", "ipcidr", "geoip/cloudflare.mrs"),
        "docker": provider("docker", "domain", "geosite/docker.mrs"),
        "npmjs": provider("npmjs", "domain", "geosite/npmjs.mrs"),
        "dropbox": provider("dropbox", "domain", "geosite/dropbox.mrs"),
        "notion": provider("notion", "domain", "geosite/notion.mrs"),
        "paypal": provider("paypal", "domain", "geosite/paypal.mrs"),
        "stripe": provider("stripe", "domain", "geosite/stripe.mrs"),
        "wise": provider("wise", "domain", "geosite/wise.mrs"),
        "binance": provider("binance", "domain", "geosite/binance.mrs"),
        "category-scholar-!cn": provider("category-scholar-!cn", "domain", "geosite/category-scholar-!cn.mrs"),
        "coursera": provider("coursera", "domain", "geosite/coursera.mrs"),
        "udemy": provider("udemy", "domain", "geosite/udemy.mrs"),
        "edx": provider("edx", "domain", "geosite/edx.mrs"),
        "khanacademy": provider("khanacademy", "domain", "geosite/khanacademy.mrs"),
        "wikimedia": provider("wikimedia", "domain", "geosite/wikimedia.mrs"),
        "bbc": provider("bbc", "domain", "geosite/bbc.mrs"),
        "cnn": provider("cnn", "domain", "geosite/cnn.mrs"),
        "nytimes": provider("nytimes", "domain", "geosite/nytimes.mrs"),
        "wsj": provider("wsj", "domain", "geosite/wsj.mrs"),
        "bloomberg": provider("bloomberg", "domain", "geosite/bloomberg.mrs"),
        "amazon": provider("amazon", "domain", "geosite/amazon.mrs"),
        "ebay": provider("ebay", "domain", "geosite/ebay.mrs"),
    }


def _build_clash_meta_rules() -> list[str]:
    return [
        "RULE-SET,category-ads-all,🛑 广告拦截",
        "RULE-SET,category-ai-chat-!cn,🤖 AI 服务",
        "RULE-SET,openai,🤖 AI 服务",
        "RULE-SET,anthropic,🤖 AI 服务",
        "RULE-SET,youtube,📹 油管视频",
        "RULE-SET,google,🔍 谷歌服务",
        "RULE-SET,google-ip,🔍 谷歌服务,no-resolve",
        "RULE-SET,microsoft,Ⓜ️ 微软服务",
        "RULE-SET,onedrive,Ⓜ️ 微软服务",
        "RULE-SET,apple,🍏 苹果服务",
        "RULE-SET,icloud,🍏 苹果服务",
        "RULE-SET,telegram,📲 电报消息",
        "RULE-SET,telegram-ip,📲 电报消息,no-resolve",
        "RULE-SET,twitter,🐦 推特/X",
        "RULE-SET,twitter-ip,🐦 推特/X,no-resolve",
        "RULE-SET,facebook,📘 Meta 系",
        "RULE-SET,instagram,📘 Meta 系",
        "RULE-SET,whatsapp,📘 Meta 系",
        "RULE-SET,facebook-ip,📘 Meta 系,no-resolve",
        "RULE-SET,discord,🎙️ Discord",
        "RULE-SET,reddit,💬 其他社交",
        "RULE-SET,linkedin,💬 其他社交",
        "RULE-SET,tiktok,💬 其他社交",
        "RULE-SET,line,💬 其他社交",
        "RULE-SET,netflix,🎬 奈飞",
        "RULE-SET,netflix-ip,🎬 奈飞,no-resolve",
        "RULE-SET,steam,🎮 Steam",
        "RULE-SET,github,🐱 代码托管",
        "RULE-SET,gitlab,🐱 代码托管",
        "RULE-SET,aws,☁️ 云服务",
        "RULE-SET,azure,☁️ 云服务",
        "RULE-SET,cloudflare,☁️ 云服务",
        "RULE-SET,cloudflare-ip,☁️ 云服务,no-resolve",
        "RULE-SET,docker,🛠️ 开发工具",
        "RULE-SET,npmjs,🛠️ 开发工具",
        "RULE-SET,dropbox,💾 网盘存储",
        "RULE-SET,notion,💾 网盘存储",
        "RULE-SET,paypal,💳 支付平台",
        "RULE-SET,stripe,💳 支付平台",
        "RULE-SET,wise,💳 支付平台",
        "RULE-SET,binance,₿ 加密货币",
        "RULE-SET,category-scholar-!cn,📚 教育学术",
        "RULE-SET,coursera,📚 教育学术",
        "RULE-SET,udemy,📚 教育学术",
        "RULE-SET,edx,📚 教育学术",
        "RULE-SET,khanacademy,📚 教育学术",
        "RULE-SET,wikimedia,📚 教育学术",
        "RULE-SET,bbc,📰 新闻资讯",
        "RULE-SET,cnn,📰 新闻资讯",
        "RULE-SET,nytimes,📰 新闻资讯",
        "RULE-SET,wsj,📰 新闻资讯",
        "RULE-SET,bloomberg,📰 新闻资讯",
        "RULE-SET,amazon,🛒 海淘购物",
        "RULE-SET,ebay,🛒 海淘购物",
        "RULE-SET,private,🏠 私有网络",
        "RULE-SET,private-ip,🏠 私有网络,no-resolve",
        "RULE-SET,geolocation-cn,🔒 国内服务",
        "RULE-SET,cn-ip,🔒 国内服务,no-resolve",
        "RULE-SET,cn,🔒 国内服务",
        "RULE-SET,geolocation-!cn,🌍 非中国",
        "MATCH,🐟 漏网之鱼",
    ]


def _build_clash_meta_config(proxies: list[dict[str, Any]], source_nodes: int, skipped_nodes: int) -> dict[str, Any]:
    proxy_names = [str(p.get("name") or "") for p in proxies if str(p.get("name") or "").strip()]
    cfg = {
        "mixed-port": 7897,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "strict",
        "dns": {
            "enable": True,
            "listen": "127.0.0.1:5335",
            "use-system-hosts": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["180.76.76.76", "182.254.118.118", "8.8.8.8", "180.184.2.2"],
            "nameserver": [
                "180.76.76.76",
                "119.29.29.29",
                "223.5.5.5",
                "8.8.8.8",
                "https://223.6.6.6/dns-query#h3=true",
                "https://dns.alidns.com/dns-query",
                "https://cloudflare-dns.com/dns-query",
                "https://doh.pub/dns-query",
            ],
            "fallback": [
                "https://000000.dns.nextdns.io/dns-query#h3=true",
                "https://dns.alidns.com/dns-query",
                "https://doh.pub/dns-query",
                "https://cloudflare-dns.com/dns-query",
                "https://dns.google/dns-query",
                "tls://8.8.4.4",
                "tls://1.0.0.1:853",
            ],
            "fallback-filter": {
                "geoip": True,
                "ipcidr": ["240.0.0.0/4", "0.0.0.0/32", "127.0.0.1/32"],
                "domain": ["+.google.com", "+.facebook.com", "+.twitter.com", "+.youtube.com"],
            },
            "fake-ip-filter": [
                "*.lan",
                "stun.*.*",
                "stun.*.*.*",
                "time.windows.com",
                "time.apple.com",
                "time.google.com",
                "pool.ntp.org",
                "ntp.aliyun.com",
                "music.163.com",
                "*.music.163.com",
                "*.msftconnecttest.com",
                "*.msftncsi.com",
            ],
        },
        "profile": {
            "store-selected": True,
            "store-fake-ip": False,
        },
        "sniffer": {
            "enable": True,
            "parse-pure-ip": True,
            "sniff": {
                "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
                "QUIC": {"ports": [443, 8443]},
                "TLS": {"ports": [443, 8443]},
            },
        },
        "geodata-mode": True,
        "geo-auto-update": True,
        "geodata-loader": "standard",
        "geo-update-interval": 24,
        "geox-url": {
            "geoip": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
            "geosite": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
            "mmdb": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
            "asn": "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb",
        },
        "proxies": proxies,
        "proxy-groups": _build_clash_meta_groups(proxy_names),
        "rule-providers": _build_clash_meta_rule_providers(),
        "rules": _build_clash_meta_rules(),
        "subhub": {
            "generated_at": _now_iso(),
            "source_nodes": source_nodes,
            "parsed_nodes": len(proxies),
            "skipped_nodes": skipped_nodes,
        },
    }
    return cfg


class SubHubService:
    def __init__(self, state_path: Path) -> None:
        self._state_path = state_path
        self._lock = asyncio.Lock()
        self._state = self._load_state()

        self._cache_ttl_seconds = 60
        self._cache_signature = ""
        self._cache_ts = 0.0
        self._cache_links: list[str] = []
        self._cache_errors: list[str] = []

    def _load_state(self) -> dict[str, Any]:
        if not self._state_path.is_file():
            return self._fresh_state()
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
        except Exception:
            return self._fresh_state()

        if not isinstance(raw, dict):
            return self._fresh_state()

        token = str(raw.get("token") or "").strip() or secrets.token_urlsafe(24)
        sources_raw = raw.get("sources") if isinstance(raw.get("sources"), list) else []
        sources: list[dict[str, Any]] = []
        for item in sources_raw:
            if not isinstance(item, dict):
                continue
            source_id = str(item.get("id") or "").strip()
            url = str(item.get("url") or "").strip()
            if not source_id or not url:
                continue
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue

            last_test = item.get("last_test") if isinstance(item.get("last_test"), dict) else None
            sources.append(
                {
                    "id": source_id,
                    "name": _cleanup_name(str(item.get("name") or ""), source_id),
                    "url": url,
                    "enabled": bool(item.get("enabled", True)),
                    "created_at": str(item.get("created_at") or _now_iso()),
                    "updated_at": str(item.get("updated_at") or _now_iso()),
                    "last_test": last_test,
                }
            )

        state = {
            "token": token,
            "sources": sources,
            "updated_at": str(raw.get("updated_at") or _now_iso()),
        }
        self._save_state(state)
        return state

    def _fresh_state(self) -> dict[str, Any]:
        state = {
            "token": secrets.token_urlsafe(24),
            "sources": [],
            "updated_at": _now_iso(),
        }
        self._save_state(state)
        return state

    def _save_state(self, state: dict[str, Any]) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _build_links(base_url: str, token: str) -> dict[str, str]:
        root = str(base_url or "").rstrip("/")
        if not root:
            root = ""
        return {
            "nekobox": f"{root}/sub/{token}/nekobox",
            "v2ray": f"{root}/sub/{token}/v2ray",
            "xray": f"{root}/sub/{token}/xray",
            "raw": f"{root}/sub/{token}/raw",
            "clash": f"{root}/sub/{token}/clash",
            "singbox": f"{root}/sub/{token}/singbox",
            "singboxfull": f"{root}/sub/{token}/singboxfull",
        }

    async def get_state(self, base_url: str) -> dict[str, Any]:
        async with self._lock:
            token = str(self._state.get("token") or "")
            sources = list(self._state.get("sources") or [])
        ok_tests = 0
        fail_tests = 0
        enabled = 0
        for item in sources:
            if item.get("enabled"):
                enabled += 1
            last_test = item.get("last_test") if isinstance(item.get("last_test"), dict) else None
            if not last_test:
                continue
            if last_test.get("ok"):
                ok_tests += 1
            else:
                fail_tests += 1

        return {
            "ok": True,
            "token": token,
            "sources": sources,
            "stats": {
                "total": len(sources),
                "enabled": enabled,
                "tested_ok": ok_tests,
                "tested_fail": fail_tests,
                "updated_at": str(self._state.get("updated_at") or ""),
            },
            "export_links": self._build_links(base_url, token),
        }

    async def add_source(self, name: str, url: str) -> dict[str, Any]:
        url = str(url or "").strip()
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("订阅 URL 必须是 http/https")

        source = {
            "id": f"src_{secrets.token_hex(6)}",
            "name": _cleanup_name(name, parsed.netloc),
            "url": url,
            "enabled": True,
            "created_at": _now_iso(),
            "updated_at": _now_iso(),
            "last_test": None,
        }

        async with self._lock:
            sources: list[dict[str, Any]] = self._state["sources"]
            for item in sources:
                if str(item.get("url") or "").strip() == url:
                    raise ValueError("该订阅地址已存在")
            sources.append(source)
            self._state["updated_at"] = _now_iso()
            self._save_state(self._state)
            self._invalidate_cache_unlocked()
        return source

    async def update_source(self, source_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        async with self._lock:
            target: dict[str, Any] | None = None
            for item in self._state["sources"]:
                if item.get("id") == source_id:
                    target = item
                    break
            if not target:
                return None

            if "url" in payload:
                next_url = str(payload.get("url") or "").strip()
                parsed = urlsplit(next_url)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    raise ValueError("订阅 URL 必须是 http/https")
                for other in self._state["sources"]:
                    if other is target:
                        continue
                    if str(other.get("url") or "").strip() == next_url:
                        raise ValueError("该订阅地址已存在")
                target["url"] = next_url

            if "name" in payload:
                fallback = urlsplit(str(target.get("url") or "")).netloc or source_id
                target["name"] = _cleanup_name(str(payload.get("name") or ""), fallback)

            if "enabled" in payload:
                target["enabled"] = bool(payload.get("enabled"))

            target["updated_at"] = _now_iso()
            self._state["updated_at"] = _now_iso()
            self._save_state(self._state)
            self._invalidate_cache_unlocked()
            return dict(target)

    async def delete_source(self, source_id: str) -> bool:
        async with self._lock:
            before = len(self._state["sources"])
            self._state["sources"] = [x for x in self._state["sources"] if x.get("id") != source_id]
            after = len(self._state["sources"])
            if after == before:
                return False
            self._state["updated_at"] = _now_iso()
            self._save_state(self._state)
            self._invalidate_cache_unlocked()
            return True

    async def rotate_token(self) -> str:
        async with self._lock:
            token = secrets.token_urlsafe(24)
            self._state["token"] = token
            self._state["updated_at"] = _now_iso()
            self._save_state(self._state)
            self._invalidate_cache_unlocked()
            return token

    @staticmethod
    async def _read_limited_text(resp: aiohttp.ClientResponse, max_bytes: int = MAX_RESPONSE_BYTES) -> str:
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.content.iter_chunked(65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                rest = len(chunk) - (total - max_bytes)
                if rest > 0:
                    chunks.append(chunk[:rest])
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="ignore")

    async def _probe_url(self, url: str, timeout: int = DEFAULT_FETCH_TIMEOUT) -> dict[str, Any]:
        start = time.perf_counter()
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        headers = {
            "User-Agent": "SubHub/1.0 (+https://3x-ui-subhub.local)",
            "Accept": "*/*",
        }

        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg, headers=headers) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    text = await self._read_limited_text(resp)
                    links = _extract_links(text)
                    latency_ms = int((time.perf_counter() - start) * 1000)
                    ok = resp.status == 200 and len(links) > 0
                    return {
                        "ok": ok,
                        "status_code": int(resp.status),
                        "latency_ms": latency_ms,
                        "checked_at": _now_iso(),
                        "node_count": len(links),
                        "message": "可用" if ok else ("返回为空或格式无法识别" if resp.status == 200 else f"HTTP {resp.status}"),
                    }
        except Exception as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            return {
                "ok": False,
                "status_code": 0,
                "latency_ms": latency_ms,
                "checked_at": _now_iso(),
                "node_count": 0,
                "message": str(exc),
            }

    async def test_source(self, source_id: str) -> dict[str, Any] | None:
        async with self._lock:
            source = next((x for x in self._state["sources"] if x.get("id") == source_id), None)
            if not source:
                return None
            url = str(source.get("url") or "")

        result = await self._probe_url(url)

        async with self._lock:
            source = next((x for x in self._state["sources"] if x.get("id") == source_id), None)
            if not source:
                return None
            source["last_test"] = result
            source["updated_at"] = _now_iso()
            self._state["updated_at"] = _now_iso()
            self._save_state(self._state)
            return dict(source)

    async def test_all(self) -> dict[str, Any]:
        async with self._lock:
            targets = [dict(x) for x in self._state.get("sources") or []]

        semaphore = asyncio.Semaphore(6)

        async def _run(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
            async with semaphore:
                result = await self._probe_url(str(item.get("url") or ""))
                return str(item.get("id") or ""), result

        pairs = await asyncio.gather(*[_run(item) for item in targets]) if targets else []
        result_map = {sid: res for sid, res in pairs if sid}

        async with self._lock:
            ok_count = 0
            fail_count = 0
            for item in self._state["sources"]:
                sid = str(item.get("id") or "")
                if sid in result_map:
                    item["last_test"] = result_map[sid]
                    item["updated_at"] = _now_iso()
                last_test = item.get("last_test") if isinstance(item.get("last_test"), dict) else None
                if last_test and last_test.get("ok"):
                    ok_count += 1
                elif last_test:
                    fail_count += 1

            self._state["updated_at"] = _now_iso()
            self._save_state(self._state)

        return {
            "ok": True,
            "tested": len(result_map),
            "ok_count": ok_count,
            "fail_count": fail_count,
        }

    def _signature(self, sources: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for item in sources:
            if not item.get("enabled"):
                continue
            parts.append(str(item.get("id") or ""))
            parts.append(str(item.get("url") or ""))
            parts.append(str(item.get("updated_at") or ""))
        return "|".join(parts)

    def _invalidate_cache_unlocked(self) -> None:
        self._cache_ts = 0.0
        self._cache_signature = ""
        self._cache_links = []
        self._cache_errors = []

    async def _fetch_links_from_url(self, url: str) -> tuple[list[str], str]:
        timeout_cfg = aiohttp.ClientTimeout(total=DEFAULT_FETCH_TIMEOUT)
        headers = {
            "User-Agent": "SubHub/1.0 (+https://3x-ui-subhub.local)",
            "Accept": "*/*",
        }
        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg, headers=headers) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    text = await self._read_limited_text(resp)
                    links = _extract_links(text)
                    if resp.status != 200:
                        return [], f"{url} -> HTTP {resp.status}"
                    if not links:
                        return [], f"{url} -> 返回为空或非订阅格式"
                    return links, ""
        except Exception as exc:
            return [], f"{url} -> {exc}"

    async def aggregate_links(self) -> tuple[list[str], list[str]]:
        async with self._lock:
            sources = [dict(x) for x in self._state.get("sources") or [] if x.get("enabled")]
            signature = self._signature(sources)
            cache_valid = (
                signature == self._cache_signature and (time.time() - self._cache_ts) <= self._cache_ttl_seconds
            )
            if cache_valid:
                return list(self._cache_links), list(self._cache_errors)

        semaphore = asyncio.Semaphore(6)

        async def _task(source: dict[str, Any]) -> tuple[list[str], str]:
            async with semaphore:
                return await self._fetch_links_from_url(str(source.get("url") or ""))

        results = await asyncio.gather(*[_task(item) for item in sources]) if sources else []

        merged: list[str] = []
        errors: list[str] = []
        seen: set[str] = set()
        for links, err in results:
            if err:
                errors.append(err)
            for link in links:
                if link in seen:
                    continue
                seen.add(link)
                merged.append(link)

        async with self._lock:
            self._cache_signature = signature
            self._cache_ts = time.time()
            self._cache_links = list(merged)
            self._cache_errors = list(errors)

        return merged, errors

    async def export_payload(self, fmt: str) -> tuple[str, str, str]:
        links, _ = await self.aggregate_links()
        raw_text = "\n".join(links).strip()
        fmt = str(fmt or "").strip().lower()

        if fmt == "raw":
            return raw_text, "text/plain; charset=utf-8", "merged-raw.txt"

        if fmt in {"nekobox", "xray", "v2ray"}:
            rebuilt_links, _, _ = _repack_share_links(links, nekobox_compat=(fmt == "nekobox"))
            prepared: list[str] = []
            seen: set[str] = set()
            for item in rebuilt_links:
                sanitized = _sanitize_link_for_nekobox(item)
                if not sanitized or sanitized in seen:
                    continue
                seen.add(sanitized)
                prepared.append(sanitized)
            text = "\n".join(prepared).strip()
            encoded = base64.b64encode(text.encode("utf-8")).decode("ascii") if text else ""
            if fmt == "nekobox":
                return encoded, "text/plain; charset=utf-8", "merged-nekobox.txt"
            name = "merged-v2ray.txt" if fmt == "v2ray" else "merged-xray.txt"
            return encoded, "text/plain; charset=utf-8", name

        nodes: list[dict[str, Any]] = []
        parse_skipped = 0
        for item in links:
            node = _parse_node(item)
            if node:
                nodes.append(node)
            else:
                parse_skipped += 1

        if fmt == "clash":
            proxies, skipped = _to_clash_proxies(nodes)
            cfg = _build_clash_meta_config(proxies, len(links), skipped + parse_skipped)
            text = yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False)
            return text, "text/yaml; charset=utf-8", "merged-clash.yaml"

        if fmt in {"singbox", "singboxfull"}:
            if fmt == "singbox":
                outbounds, skipped, _ = _to_singbox_outbounds(nodes, nekobox_compat=True)
                # Keep `singbox` endpoint as a pure outbounds subscription for NekoBox parsing.
                return (
                    json.dumps({"outbounds": outbounds}, ensure_ascii=False, indent=2),
                    "application/json; charset=utf-8",
                    "merged-singbox-outbounds.json",
                )
            outbounds, skipped, tags = _to_singbox_outbounds(nodes)
            cfg = {
                "log": {"disabled": False, "level": "info"},
                "inbounds": [
                    {
                        "type": "mixed",
                        "tag": "mixed-in",
                        "listen": "127.0.0.1",
                        "listen_port": 2080,
                    }
                ],
                "outbounds": [
                    {"type": "selector", "tag": "select", "outbounds": tags if tags else ["direct"]},
                    *outbounds,
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"},
                ],
                "route": {
                    "final": "select",
                    "auto_detect_interface": True,
                },
                "subhub": {
                    "generated_at": _now_iso(),
                    "source_nodes": len(links),
                    "parsed_nodes": len(outbounds),
                    "skipped_nodes": skipped + parse_skipped,
                },
            }
            return json.dumps(cfg, ensure_ascii=False, indent=2), "application/json; charset=utf-8", "merged-singbox-full.json"

        raise ValueError("unsupported format")

    async def verify_token(self, token: str) -> bool:
        async with self._lock:
            return str(self._state.get("token") or "") == str(token or "")
