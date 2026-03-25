from __future__ import annotations

import json
from pathlib import Path

from aiohttp import web

from config import BASE_DIR, AppConfig, load_config, save_config
from security import build_session_token, hash_password, parse_session_token, verify_password
from subhub_service import SubHubService


TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
SESSION_COOKIE = "subhub_session"


class AppContext:
    def __init__(self) -> None:
        self.cfg: AppConfig = load_config()
        self.subhub = SubHubService(BASE_DIR / "subhub_data.json")



def _json(data: dict, status: int = 200) -> web.Response:
    return web.json_response(data, status=status, dumps=lambda obj: json.dumps(obj, ensure_ascii=False))


async def _json_body(request: web.Request) -> dict:
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _request_base_url(request: web.Request) -> str:
    proto = str(request.headers.get("X-Forwarded-Proto") or request.scheme or "http").split(",")[0].strip()
    host = str(request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or request.host or "").split(",")[0].strip()
    if not host:
        host = "127.0.0.1"
    return f"{proto}://{host}"


def _read_html(name: str) -> str:
    return (TEMPLATES_DIR / name).read_text(encoding="utf-8")


def _session_user(request: web.Request) -> str:
    ctx: AppContext = request.app["ctx"]
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return ""

    payload = parse_session_token(token, ctx.cfg.session_secret)
    if not payload:
        return ""

    user = str(payload.get("u") or "").strip()
    if user != ctx.cfg.admin_user:
        return ""
    return user


def _require_auth(request: web.Request) -> str:
    user = _session_user(request)
    if not user:
        raise web.HTTPUnauthorized(
            text=json.dumps({"ok": False, "error": "unauthorized"}, ensure_ascii=False),
            content_type="application/json",
        )
    return user


async def page_root(request: web.Request) -> web.Response:
    if not _session_user(request):
        raise web.HTTPFound("/login")
    return web.Response(text=_read_html("dashboard.html"), content_type="text/html")


async def page_login(request: web.Request) -> web.Response:
    if _session_user(request):
        raise web.HTTPFound("/")
    return web.Response(text=_read_html("login.html"), content_type="text/html")


async def api_login(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    payload = await _json_body(request)

    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")

    if username != ctx.cfg.admin_user or not verify_password(password, ctx.cfg.admin_password_hash):
        return _json({"ok": False, "error": "用户名或密码错误"}, status=401)

    token = build_session_token(ctx.cfg.admin_user, ctx.cfg.session_secret, int(ctx.cfg.session_ttl_seconds))
    resp = _json({"ok": True, "user": ctx.cfg.admin_user})
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(ctx.cfg.session_ttl_seconds),
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/",
    )
    return resp


async def api_logout(request: web.Request) -> web.Response:
    _require_auth(request)
    resp = _json({"ok": True})
    resp.del_cookie(SESSION_COOKIE, path="/")
    return resp


async def api_change_password(request: web.Request) -> web.Response:
    _require_auth(request)
    ctx: AppContext = request.app["ctx"]
    payload = await _json_body(request)

    current_password = str(payload.get("current_password") or "")
    new_password = str(payload.get("new_password") or "")
    confirm_password = str(payload.get("confirm_password") or "")

    if not verify_password(current_password, ctx.cfg.admin_password_hash):
        return _json({"ok": False, "error": "当前密码不正确"}, status=400)
    if len(new_password) < 8:
        return _json({"ok": False, "error": "新密码长度至少 8 位"}, status=400)
    if new_password != confirm_password:
        return _json({"ok": False, "error": "两次输入的新密码不一致"}, status=400)
    if new_password == current_password:
        return _json({"ok": False, "error": "新密码不能与当前密码相同"}, status=400)

    ctx.cfg.admin_password_hash = hash_password(new_password)
    save_config(ctx.cfg)
    return _json({"ok": True})


async def api_healthz(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    return _json({"ok": True, "service": "subhub-panel", "port": int(ctx.cfg.port)})


async def api_subhub_state(request: web.Request) -> web.Response:
    _require_auth(request)
    ctx: AppContext = request.app["ctx"]
    data = await ctx.subhub.get_state(_request_base_url(request))
    return _json(data)


async def api_subhub_add_source(request: web.Request) -> web.Response:
    _require_auth(request)
    ctx: AppContext = request.app["ctx"]
    payload = await _json_body(request)

    name = str(payload.get("name") or "").strip()
    url = str(payload.get("url") or "").strip()
    if not url:
        return _json({"ok": False, "error": "url 不能为空"}, status=400)

    try:
        source = await ctx.subhub.add_source(name=name, url=url)
    except ValueError as e:
        return _json({"ok": False, "error": str(e)}, status=400)

    return _json({"ok": True, "source": source})


async def api_subhub_update_source(request: web.Request) -> web.Response:
    _require_auth(request)
    ctx: AppContext = request.app["ctx"]

    source_id = str(request.match_info.get("source_id") or "").strip()
    if not source_id:
        return _json({"ok": False, "error": "source_id 不能为空"}, status=400)

    payload = await _json_body(request)
    allowed: dict = {}
    if "name" in payload:
        allowed["name"] = payload.get("name")
    if "url" in payload:
        allowed["url"] = payload.get("url")
    if "enabled" in payload:
        allowed["enabled"] = payload.get("enabled")
    if not allowed:
        return _json({"ok": False, "error": "无可更新字段"}, status=400)

    try:
        source = await ctx.subhub.update_source(source_id, allowed)
    except ValueError as e:
        return _json({"ok": False, "error": str(e)}, status=400)

    if not source:
        return _json({"ok": False, "error": "source not found"}, status=404)

    return _json({"ok": True, "source": source})


async def api_subhub_delete_source(request: web.Request) -> web.Response:
    _require_auth(request)
    ctx: AppContext = request.app["ctx"]

    source_id = str(request.match_info.get("source_id") or "").strip()
    if not source_id:
        return _json({"ok": False, "error": "source_id 不能为空"}, status=400)

    ok = await ctx.subhub.delete_source(source_id)
    if not ok:
        return _json({"ok": False, "error": "source not found"}, status=404)

    return _json({"ok": True})


async def api_subhub_test_source(request: web.Request) -> web.Response:
    _require_auth(request)
    ctx: AppContext = request.app["ctx"]

    source_id = str(request.match_info.get("source_id") or "").strip()
    if not source_id:
        return _json({"ok": False, "error": "source_id 不能为空"}, status=400)

    source = await ctx.subhub.test_source(source_id)
    if not source:
        return _json({"ok": False, "error": "source not found"}, status=404)

    return _json({"ok": True, "source": source})


async def api_subhub_test_all(request: web.Request) -> web.Response:
    _require_auth(request)
    ctx: AppContext = request.app["ctx"]
    result = await ctx.subhub.test_all()
    return _json(result)


async def api_subhub_rotate_token(request: web.Request) -> web.Response:
    _require_auth(request)
    ctx: AppContext = request.app["ctx"]
    token = await ctx.subhub.rotate_token()
    state = await ctx.subhub.get_state(_request_base_url(request))
    links = state.get("export_links") if isinstance(state, dict) else {}
    return _json({"ok": True, "token": token, "export_links": links})


async def api_sub_export(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]

    token = str(request.match_info.get("token") or "").strip()
    fmt = str(request.match_info.get("fmt") or "xray").strip().lower() or "xray"

    if fmt not in {"xray", "v2ray", "raw", "clash", "singbox"}:
        return _json({"ok": False, "error": "unsupported format"}, status=400)

    if not await ctx.subhub.verify_token(token):
        raise web.HTTPNotFound(text="not found")

    text, content_type, filename = await ctx.subhub.export_payload(fmt)
    resp = web.Response(text=text)
    resp.headers["Content-Type"] = content_type
    resp.headers["Content-Disposition"] = f'inline; filename="{filename}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


def create_app() -> web.Application:
    app = web.Application(client_max_size=2 * 1024 * 1024)
    app["ctx"] = AppContext()

    app.router.add_get("/", page_root)
    app.router.add_get("/login", page_login)

    app.router.add_get("/healthz", api_healthz)
    app.router.add_post("/api/login", api_login)
    app.router.add_post("/api/logout", api_logout)
    app.router.add_post("/api/account/password", api_change_password)

    app.router.add_get("/api/subhub/state", api_subhub_state)
    app.router.add_post("/api/subhub/sources", api_subhub_add_source)
    app.router.add_put("/api/subhub/sources/{source_id}", api_subhub_update_source)
    app.router.add_delete("/api/subhub/sources/{source_id}", api_subhub_delete_source)
    app.router.add_post("/api/subhub/test/{source_id}", api_subhub_test_source)
    app.router.add_post("/api/subhub/test-all", api_subhub_test_all)
    app.router.add_post("/api/subhub/token/rotate", api_subhub_rotate_token)

    app.router.add_get("/sub/{token}", api_sub_export)
    app.router.add_get("/sub/{token}/{fmt}", api_sub_export)

    app.router.add_static("/static/", str(STATIC_DIR), show_index=False)
    return app


def main() -> None:
    app = create_app()
    ctx: AppContext = app["ctx"]
    web.run_app(app, host=str(ctx.cfg.host), port=int(ctx.cfg.port), access_log=None)


if __name__ == "__main__":
    main()
