# zcode — headless 服务器上的 ZCode 管理工具（基于官方 WebUI 远控中继）
#
# 用法:
#   zcode              统一入口: 确保已登录 → 已注册远控 → 应用已启动, 最后输出远控链接
#                      --rotate   强制重新注册远控设备（换绑）
#                      --relogin  强制重新走 BigModel 登录（换账号/凭据损坏时用）
#   zcode stop         停止 ZCode
#   zcode restart      重启 ZCode
#   zcode update       更新到最新版本（运行中会自动重启；未安装时直接引导安装）
#
# 原理（详见项目 README）:
#   - 登录（BigModel OAuth，协议逆向自官方客户端，经 chenrensong/zcode-helper 交叉验证）:
#       打开 https://bigmodel.cn/login?redirect=…（经 zcode.z.ai 中转, 回调 zcode://oauth/callback）
#       → 粘贴回调链接或 code → POST {ENDPOINT}/api/v1/oauth/token {provider:'bigmodel',code,…}
#       → 换 token、派生 coding-plan key（getCustomerInfo → 默认机构/项目 → zcode-api-key copy）
#       → enc:v1 加密写入 credentials.json / config.json / setting.json（merge, 不覆盖已有 key）
#   - 远控中继客户端在 Electron 主进程里，随应用启动自动恢复上次开启的远控
#     （setting.json: webRemoteControlLastEnabledContext），无需 GUI 点击。
#   - 远控注册可替代"首次去 GUI 里点一下": 直连官方 relay (wss://…/ws) 完成设备
#     注册握手并把凭据写成应用原生格式，应用下次启动即走原生恢复路径:
#         C:{type:"device_register_init",device_mid,pass_hash,meta,client_ts}
#         S:{type:"device_register_ack",device_sid}
#         C:{type:"auth_init",role:"device",device_sid,meta,client_ts}
#         S:{type:"auth_challenge",nonce}
#         C:{type:"auth_response",device_sid,proof=base64url(HMAC-SHA256(pass_hash, "nonce|device|sid")),client_ts}
#         S:{type:"auth_ack",pair_status:"waiting"}     ← 注册完成，等待手机配对
#     relay 是设备级信任（只认 pass_hash），全程不需要账号 token。
#   - 链接参数全部持久化，可离线重建:
#       sid   = ~/.zcode/v2/setting.json     webRemoteControlExternalRelayDevice.deviceSid
#       hash  = ~/.zcode/v2/credentials.json web-remote-control:external-relay:pass_hash
#               （enc:v1 AES-256-GCM，密钥 = sha256("zcode-credential-fallback:linux:$HOME:$USER")）
#       mid   = ~/.zcode/v2/telemetry-state.json deviceMid
#       name  = hostname；t = 当前时间戳；app_version = AppImage 版本
#   - headless 下通过 Xvfb 运行完整 GUI（浏览器控制等 GUI 能力得以保留），
#     APPIMAGE_EXTRACT_AND_RUN=1 免 FUSE，且更新可直接换文件。
#   - 更新走官方 manifest: GET {endpoint}/api/v1/releases/electron/manifest
#       ?platform=linux-x64&channel=latest  （YAML，含 AppImage 直链与 sha512）
#
# 依赖: uv（cryptography / pyyaml 由上方脚本元数据自动安装隔离）；
#       无显示器的主机需要 Xvfb（Fedora: sudo dnf install xorg-x11-server-Xvfb；
#       Debian: sudo apt install xvfb）。

import base64
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENDPOINT = os.environ.get("ZCODE_ENDPOINT", "https://zcode.z.ai")

# ---------- 登录（BigModel OAuth）相关常量 ----------
TOKEN_URL = f"{ENDPOINT}/api/v1/oauth/token"
CALLBACK_URI = "zcode://oauth/callback"
BIGMODEL_AUTHORIZE = "https://bigmodel.cn/login"
BIGMODEL_USERINFO = "https://open.bigmodel.cn/api/biz/customer/getCustomerInfo"
BIGMODEL_BASE = "https://open.bigmodel.cn"
PROVIDERS_BIGMODEL = {
    "builtin:bigmodel": {"enabled": True, "baseURL": "https://open.bigmodel.cn/api/anthropic", "apiKey": False},
    "builtin:bigmodel-coding-plan": {"enabled": True, "baseURL": "https://open.bigmodel.cn/api/anthropic", "apiKey": "clear"},
    "builtin:bigmodel-start-plan": {"enabled": False, "baseURL": "https://zcode.z.ai/api/v1/zcode-plan/anthropic", "apiKey": True},
}
ALL_PROVIDER_IDS = [
    "builtin:zai", "builtin:zai-coding-plan", "builtin:zai-start-plan",
    "builtin:bigmodel", "builtin:bigmodel-coding-plan", "builtin:bigmodel-start-plan",
]

ZCODE_DIR = Path.home() / ".zcode"
V2_DIR = ZCODE_DIR / "v2"
CTL_DIR = ZCODE_DIR / "headless"
STATE_FILE = CTL_DIR / "state.json"
APP_LOG = CTL_DIR / "app.log"
APPS_DIR = Path.home() / "Applications"
APPIMAGE_RE = re.compile(r"ZCode-([\d.]+)-linux-x\d+\.AppImage$")
# extract-and-run 模式下真正的 Electron 进程在 /tmp/appimage_extracted_*/ 里，
# cmdline 不含 AppImage 路径，必须单独匹配
RUNNING_RE = re.compile(r"(ZCode-[\d.]+-linux-x\d+\.AppImage|/\.mount_ZCode-|/appimage_extracted_[0-9a-z]+/)")
READY_TIMEOUT = 240  # extract-and-run 冷启动解压较慢（200MB），慢盘上可达 2 分钟以上


def log(msg, file=None):
    print(msg, file=file, flush=True)


def die(msg, code=1):
    print(f"✗ {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


# ---------- 进程发现 ----------

def _proc_uid(pid_dir):
    try:
        m = re.search(r"^Uid:\s*(\d+)", (pid_dir / "status").read_text(), re.M)
    except OSError:
        return None
    return int(m.group(1)) if m else None


def find_running():
    """返回本用户正在运行的 ZCode 进程列表 [(pid, version|None, cmdline_token)]，按 pid 升序。

    /proc 全局可扫，必须按 uid 过滤，否则多用户共机时 status/stop 会串到其他用户的实例。
    """
    uid = os.getuid()
    out = []
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        if _proc_uid(pid_dir) != uid:
            continue
        try:
            cmdline = (pid_dir / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        for token in cmdline:
            token = token.decode("utf-8", "replace")
            if RUNNING_RE.search(token):
                m = APPIMAGE_RE.search(token)
                ver = m.group(1) if m else None
                out.append((int(pid_dir.name), ver, token))
                break
    return sorted(out)


def app_version_from_path(path):
    m = APPIMAGE_RE.search(str(path))
    return m.group(1) if m else None


# ---------- AppImage 定位 ----------

def find_appimage():
    """取 ~/Applications 下 mtime 最新的 AppImage；没有则返回 None。"""
    cands = sorted(APPS_DIR.glob("ZCode-*-linux-x*.AppImage"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0] if cands else None


# ---------- 凭据加解密（官方 enc:v1 格式） ----------

def credential_secret():
    # 与官方客户端 defaultCredentialSecret 对齐: os.platform():os.homedir():os.userInfo().username
    return f"zcode-credential-fallback:linux:{Path.home()}:{pwd.getpwuid(os.getuid()).pw_name}"


def _enc_v1_key(secret):
    return hashlib.sha256(secret.encode()).digest()


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decrypt_enc_v1(enc, secret):
    if not enc.startswith("enc:v1:"):
        raise ValueError("不是 enc:v1 格式")
    nonce, tag, ct = (_b64u_decode(x) for x in enc[7:].split("."))
    return AESGCM(_enc_v1_key(secret)).decrypt(nonce, ct + tag, None).decode()


def encrypt_enc_v1(plain, secret):
    nonce = os.urandom(12)
    sealed = AESGCM(_enc_v1_key(secret)).encrypt(nonce, plain.encode(), None)
    return f"enc:v1:{_b64u(nonce)}.{_b64u(sealed[-16:])}.{_b64u(sealed[:-16])}"


def decrypt_pass_hash():
    """解密 credentials.json 中的远控 pass_hash（即链接里的 hash 参数）。"""
    try:
        creds = json.loads((V2_DIR / "credentials.json").read_text())
    except FileNotFoundError:
        return None, "未找到 ~/.zcode/v2/credentials.json（尚未登录）"
    enc = creds.get("web-remote-control:external-relay:pass_hash")
    if not enc:
        return None, "credentials.json 中无远控凭据（远控从未开启）"
    try:
        return decrypt_enc_v1(enc, credential_secret()), None
    except Exception as e:  # noqa: BLE001
        return None, f"解密失败: {e}"


# ---------- 远控链接重建 ----------

def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def last_relay_state():
    """今天的官方日志里 relay 最近一次状态（waiting_terminal=已连接等待配对）。"""
    today = time.strftime("%Y-%m-%d.log", time.localtime())
    try:
        text = (V2_DIR / "logs" / today).read_text(errors="replace")
    except OSError:
        return None
    states = re.findall(r'external relay device state \{"state":"([a-z_]+)"\}', text)
    return states[-1] if states else None


def build_link(app_version=None, warn=True):
    """从持久化文件重建远控链接。返回 (url|None, problem|None)。"""
    setting = read_json(V2_DIR / "setting.json")
    sid = ((setting.get("webRemoteControlExternalRelayDevice") or {}).get("deviceSid") or "").strip()
    if not sid:
        return None, "远控从未开启（setting.json 无 deviceSid）——先执行 `zcode enable` 注册（无需 GUI）"
    pass_hash, err = decrypt_pass_hash()
    if not pass_hash:
        return None, err
    mid = (read_json(V2_DIR / "telemetry-state.json").get("deviceMid") or "").strip()
    qs = {
        "sid": sid,
        "hash": pass_hash,
        "t": str(int(time.time() * 1000)),
        "name": socket.gethostname(),
    }
    if mid:
        qs["mid"] = mid
    if app_version:
        qs["app_version"] = app_version
    url = f"{ENDPOINT}/remote/v4?" + urllib.parse.urlencode(qs, quote_via=urllib.parse.quote)
    return url, None


def print_link(app_version=None):
    url, problem = build_link(app_version)
    if url:
        log(url)
        state = last_relay_state()
        if state == "waiting_terminal":
            log("  （relay 已连接，等待配对）")
        elif state:
            log(f"  （relay 状态: {state}）")
        else:
            log("  （ZCode 未运行或 relay 日志未见连接记录，链接打开后将显示离线）")
    else:
        log(f"✗ 无法生成链接: {problem}", file=sys.stderr)
    return url


# ---------- 登录: BigModel OAuth（协议逆向自官方客户端） ----------

def post_json(url, body, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def get_json(url, authorization=None):
    req = urllib.request.Request(url, headers={"Authorization": authorization} if authorization else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except OSError:
        return None


def unwrap_biz(j):
    if not isinstance(j, dict):
        return None
    c = j.get("code")
    if c not in (None, 0, 200):
        return None
    return j["data"] if isinstance(j.get("data"), dict) else j


def build_authorize_url(state):
    relay = f"{ENDPOINT}/app/oauth/login?redirect={urllib.parse.quote(CALLBACK_URI, safe='')}"
    qs = urllib.parse.urlencode({"redirect": relay, "appId": "zcode", "state": state})
    return f"{BIGMODEL_AUTHORIZE}?{qs}"


def exchange_code(code, state):
    j = post_json(TOKEN_URL, {"provider": "bigmodel", "code": code,
                              "redirect_uri": CALLBACK_URI, "state": state})
    c = j.get("code")
    if c not in (None, 0, 200):
        die(f"token 交换失败: {j.get('msg') or j.get('message')}")
    d = j.get("data") or {}
    if not d.get("token"):
        die("token 响应缺少 data.token")
    bm = d.get("bigmodel") if isinstance(d.get("bigmodel"), dict) else d
    return {
        "token": d["token"],
        "accessToken": str(bm.get("access_token") or bm.get("accessToken") or ""),
        "refreshToken": bm.get("refresh_token") or bm.get("refreshToken") or None,
        "user": d.get("user") or {},
    }


def fetch_customer_info(access_token):
    return unwrap_biz(get_json(BIGMODEL_USERINFO, access_token))


def derive_coding_plan_key(access_token):
    """与官方客户端一致: getCustomerInfo → 默认机构/项目 → 找/建 zcode-api-key → copy 取 secretKey。"""
    info = fetch_customer_info(access_token)
    if not info:
        return None
    orgs = info.get("organizations") or []
    if not orgs:
        return None
    org = next((o for o in orgs if "默认机构" in str(o.get("organizationName", ""))), orgs[0])
    org_id = str(org.get("organizationId", ""))
    projects = org.get("projects") or []
    proj = next((p for p in projects if "默认项目" in str(p.get("projectName", ""))),
                projects[0] if projects else None)
    if not (org_id and proj):
        return None
    proj_id = str(proj.get("projectId", ""))
    if not proj_id:
        return None
    keys_url = f"{BIGMODEL_BASE}/api/biz/v1/organization/{org_id}/projects/{proj_id}/api_keys"
    entry = None
    lst = get_json(keys_url, access_token)
    for k in (lst.get("data") if isinstance(lst, dict) else None) or []:
        if k.get("name") == "zcode-api-key":
            entry = k
            break
    if entry is None:
        try:
            j = post_json(keys_url, {"name": "zcode-api-key"}, {"Authorization": access_token})
            if isinstance(j.get("data"), dict):
                entry = j["data"]
        except OSError:
            return None
    api_key = str((entry or {}).get("apiKey", "")).strip()
    if not api_key:
        return None
    cp = get_json(f"{keys_url}/copy/{urllib.parse.quote(api_key)}", access_token) or {}
    secret_key = str((cp.get("data") or {}).get("secretKey") or cp.get("secretKey") or "").strip()
    return f"{api_key}.{secret_key}" if secret_key else None


def to_native_user_profile(u):
    def first(*keys):
        for k in keys:
            v = u.get(k)
            if v not in (None, ""):
                return v
        return None
    uid = first("customerNumber", "customerId", "user_id", "userId", "id", "sub") or "unknown"
    name = first("customerName", "nickName", "name", "username", "displayName", "email", "mail")
    avatar = first("avatar", "avatarUrl", "picture")
    raw = u.get("rawProfile") if isinstance(u.get("rawProfile"), dict) else {}
    out = {"id": str(uid), "username": name or "user", "displayName": name or str(uid),
           "rawProfile": {**raw, "zcodeProfileSchemaVersion": 2}}
    if avatar:
        out["avatarUrl"] = avatar
    return out


def apply_credentials(creds, t, user_info, secret):
    """把登录态合并进现有 credentials dict（保留 deviceSid 等非登录 key）。"""
    for pid in ("zai", "bigmodel"):
        for sfx in ("access_token", "refresh_token", "user_info"):
            creds.pop(f"oauth:{pid}:{sfx}", None)
    creds["oauth:active_provider"] = encrypt_secret("bigmodel")
    creds["oauth:bigmodel:access_token"] = encrypt_secret(t["accessToken"])
    if t.get("refreshToken"):
        creds["oauth:bigmodel:refresh_token"] = encrypt_secret(t["refreshToken"])
    creds["zcodejwttoken"] = encrypt_secret(t["token"])
    creds["oauth:bigmodel:user_info"] = encrypt_secret(json.dumps(user_info, ensure_ascii=False))


def apply_config_providers(config, api_key):
    pm = config.setdefault("provider", {})
    for pid, spec in PROVIDERS_BIGMODEL.items():
        e = pm.setdefault(pid, {"options": {}})
        if not isinstance(e.get("options"), dict):
            e["options"] = {}
        e["enabled"] = spec["enabled"]
        if spec["apiKey"] is True and api_key:
            e["options"]["apiKey"] = api_key
        elif spec["apiKey"] is False:
            e["options"].pop("apiKey", None)
        elif spec["apiKey"] == "clear":
            e["options"]["apiKey"] = ""
        if spec["baseURL"]:
            e["options"]["baseURL"] = spec["baseURL"]
    for pid in ALL_PROVIDER_IDS:
        if pid not in PROVIDERS_BIGMODEL and isinstance(pm.get(pid), dict):
            pm[pid]["enabled"] = False


def apply_setting_provider_family(setting):
    setting["providerFamilyDomain"] = "bigmodel"
    setting["providerFamilyDomainUpdatedAt"] = int(time.time() * 1000)
    setting["providerFamilyDomainMigrated"] = True
    modes = setting.get("modelProviderFamilyModes") or {}
    modes["bigmodel"] = "oauth"
    setting["modelProviderFamilyModes"] = modes


def parse_pasted(raw):
    """接受完整回调 URL（zcode://…?code=x&state=y）、普通 URL 或纯 code。"""
    s = raw.strip()
    if "=" not in s:
        return (s or None, None)
    q = s[s.index("?") + 1:] if "?" in s else s
    params = urllib.parse.parse_qs(q)
    return ((params.get("code") or params.get("authCode") or [None])[0],
            (params.get("state") or [None])[0])


def ask_code(state):
    log("      在浏览器中完成登录后，把回调链接（以 zcode:// 开头的完整 URL）或授权码 code 粘贴到下面")
    log("      （浏览器弹出「打开 ZCode?」点取消即可；Ctrl-C 放弃本次登录）")
    while True:
        try:
            raw = input("  粘贴 > ").strip()
        except EOFError:
            die("无交互输入，已退出。可先在有浏览器的机器上完成登录后把凭据复制过来")
        if not raw:
            continue
        code, s = parse_pasted(raw)
        if not code:
            log("      ✗ 解析不出 code，请粘贴完整回调 URL 或纯 code")
            continue
        if s is not None and s != state:
            log("      ✗ state 不匹配（可能复制了旧的/别的会话链接），请重新登录并复制新的回调")
            continue
        return code


def logged_in():
    """credentials.json 里能解出 bigmodel access_token 即视为已登录。"""
    try:
        creds = json.loads((V2_DIR / "credentials.json").read_text())
    except (OSError, ValueError):
        return False
    enc = creds.get("oauth:bigmodel:access_token")
    if not enc:
        return False
    try:
        decrypt_enc_v1(enc, credential_secret())
        return True
    except Exception:  # noqa: BLE001  secret 变化/密文损坏 → 需重新登录
        return False


def do_login():
    """交互式 BigModel OAuth 登录，凭据合并写入 ~/.zcode/v2/（不覆盖已注册的远控 key）。"""
    if find_running():
        die("ZCode 正在运行，请先 `zcode stop`（运行中的应用退出时可能回写设置）")
    state = secrets.token_hex(16)
    url = build_authorize_url(state)
    log("请在浏览器中登录 BigModel 账号:")
    log(f"  {url}")
    try:
        subprocess.Popen(["xdg-open", url], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        log("  （自动打开失败，请手动复制上面的 URL 到浏览器）")
    code = ask_code(state)
    log(f"换取令牌…（授权码长度 {len(code)}）")
    t = exchange_code(code, state)
    log(f"  token ok（zcodejwttoken {len(t['token'])}B, access {len(t['accessToken'])}B"
        f"{'，refresh 有' if t['refreshToken'] else '，无 refresh'}）")
    user_raw = t["user"]
    if not user_raw.get("email") and not user_raw.get("name") and t["accessToken"]:
        user_raw = fetch_customer_info(t["accessToken"]) or user_raw
    user_info = to_native_user_profile(user_raw)
    log(f"  账号: {user_info['displayName']} (id={user_info['id']})")
    try:
        api_key = derive_coding_plan_key(t["accessToken"])
        log(f"  coding-plan key: {'已派生' if api_key else '（派生失败，降级为无 key）'}")
    except OSError as e:
        api_key = None
        log(f"  coding-plan key 派生异常（忽略）: {e}")

    secret = credential_secret()
    creds_path = V2_DIR / "credentials.json"
    creds = read_json(creds_path)
    apply_credentials(creds, t, user_info, secret)
    config_path = V2_DIR / "config.json"
    config = read_json(config_path)
    apply_config_providers(config, t["token"])
    if api_key:
        slot = (config.get("provider") or {}).get("builtin:bigmodel-coding-plan") or {}
        if isinstance(slot.get("options"), dict):
            slot["options"]["apiKey"] = api_key
    setting_path = V2_DIR / "setting.json"
    setting = read_json(setting_path)
    apply_setting_provider_family(setting)
    V2_DIR.mkdir(parents=True, exist_ok=True)
    for path, data in ((creds_path, creds), (config_path, config), (setting_path, setting)):
        _merge_json(path, data)
        os.chmod(path, 0o600)
    log("✓ 登录完成，凭据已写入 ~/.zcode/v2/")


# ---------- relay WS 最小客户端（仅实现注册/认证握手所需子集） ----------

def relay_ws_url():
    u = urllib.parse.urlsplit(ENDPOINT)
    return u.hostname, u.port or 443, "/ws"


class RelayWS:
    """标准库实现的 WebSocket 客户端，只覆盖文本帧收发与 ping/pong。"""

    def __init__(self, timeout=15):
        self.host, self.port, self.path = relay_ws_url()
        raw = socket.create_connection((self.host, self.port), timeout=timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                die("relay WS 升级被中断")
            resp += chunk
        head, self.buf = resp.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            die(f"relay WS 握手失败: {head.split(chr(13).encode())[0].decode(errors='replace')}")

    def _recv(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("relay WS 连接中断")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _send_frame(self, opcode, payload):
        mask = os.urandom(4)
        head = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 1 << 16:
            head += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            head += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(head + mask + masked)

    def _recv_frame(self):
        while True:
            b1, b2 = self._recv(2)
            opcode, masked, length = b1 & 0x0F, b2 & 0x80, b2 & 0x7F
            if length == 126:
                length = int.from_bytes(self._recv(2), "big")
            elif length == 127:
                length = int.from_bytes(self._recv(8), "big")
            if masked:
                self._recv(4)  # 服务器帧不会带掩码，防御性丢弃
            payload = self._recv(length) if length else b""
            if opcode == 0x9:  # ping -> pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0x8:  # close
                return None, None
            if opcode in (0x1, 0x2, 0x0):
                return opcode, payload

    def send_json(self, obj):
        self._send_frame(0x1, json.dumps(obj).encode())

    def recv_json(self, deadline):
        while True:
            if time.time() > deadline:
                raise TimeoutError("relay 响应超时")
            opcode, payload = self._recv_frame()
            if opcode is None:
                return None
            if opcode in (0x1, 0x2):
                return json.loads(payload)
            # 0x0 continuation 等其他帧：relay 消息均为单帧，忽略

    def close(self):
        try:
            self._send_frame(0x8, b"")
            self.sock.close()
        except OSError:
            pass


def hmac_sha256_b64url(key, message):
    import hmac as _hmac
    return base64.urlsafe_b64encode(
        _hmac.new(key.encode(), message.encode(), hashlib.sha256).digest()).decode().rstrip("=")


def relay_exchange(first_msg, proof_key, meta):
    """发送首条消息并完成 注册/持久认证 + 挑战应答 流程。返回 (sid, pair_status)。"""
    ws = RelayWS()
    try:
        ws.send_json(first_msg)
        sid, pair = None, None
        deadline = time.time() + 20
        while time.time() < deadline:
            msg = ws.recv_json(deadline)
            if msg is None:
                break
            mtype = msg.get("type")
            if mtype == "device_register_ack":
                sid = msg.get("device_sid")
                ws.send_json({"type": "auth_init", "role": "device", "device_sid": sid,
                              "meta": meta, "client_ts": int(time.time() * 1000)})
            elif mtype == "auth_challenge":
                ws.send_json({"type": "auth_response", "device_sid": sid,
                              "proof": hmac_sha256_b64url(proof_key, f"{msg.get('nonce')}|device|{sid}"),
                              "client_ts": int(time.time() * 1000)})
            elif mtype in ("auth_ack", "pair_status_ack"):
                pair = msg.get("pair_status")
                if pair == "waiting":
                    return sid, pair
            elif mtype == "error":
                die(f"relay 返回错误: {msg.get('code')} {msg.get('message')}")
        return sid, pair
    finally:
        ws.close()


# ---------- enable: relay 设备注册（替代"首次 GUI 点击"） ----------

def encrypt_secret(plain):
    """把明文按官方 enc:v1 格式加密（供写入 credentials.json）。"""
    return encrypt_enc_v1(plain, credential_secret())


def _merge_json(path, patch):
    data = read_json(path)
    data.update(patch)
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.replace(path)


def relay_registered():
    """setting.json 有 deviceSid 且 credentials.json 有远控 pass_hash 即视为已注册。"""
    sid = ((read_json(V2_DIR / "setting.json").get("webRemoteControlExternalRelayDevice") or {})
           .get("deviceSid") or "").strip()
    if not sid:
        return False
    try:
        creds = json.loads((V2_DIR / "credentials.json").read_text())
    except (OSError, ValueError):
        return False
    return bool(creds.get("web-remote-control:external-relay:pass_hash"))


def do_enable():
    V2_DIR.mkdir(parents=True, exist_ok=True)
    appimage = find_appimage()
    app_ver = app_version_from_path(appimage) if appimage else None
    password = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    pass_hash = base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()
    tele_path = V2_DIR / "telemetry-state.json"
    tele = read_json(tele_path)
    device_mid = tele.get("deviceMid") or str(uuid.uuid4())
    if tele.get("deviceMid") != device_mid:
        _merge_json(tele_path, {"deviceMid": device_mid})
    meta = {"platform": "linux", "version": app_ver or "", "name": socket.gethostname()}

    log("连接官方 relay 注册设备 …")
    try:
        sid, pair = relay_exchange(
            {"type": "device_register_init", "device_mid": device_mid,
             "pass_hash": pass_hash, "meta": meta, "client_ts": int(time.time() * 1000)},
            proof_key=pass_hash, meta=meta)
    except OSError as e:
        die(f"无法连接 relay ({ENDPOINT}): {e}")
    if not sid or pair != "waiting":
        die(f"注册未完成（sid={sid}, pair_status={pair}），凭据未写入")
    # 说明: relay 会回收"无活跃连接的未配对设备"，因此注册后无需（也无法）离线保持；
    # 即使应用首连时 sid 已被回收，应用会对 AUTH_FAILED 自动用同一 pass_hash 重新注册自愈。

    setting_path = V2_DIR / "setting.json"
    _merge_json(setting_path, {
        "webRemoteControlExternalRelayDevice": {"deviceSid": sid},
        "webRemoteControlLastEnabledContext": {"workspacePath": os.getcwd()},
    })
    creds_path = V2_DIR / "credentials.json"
    _merge_json(creds_path, {"web-remote-control:external-relay:pass_hash": encrypt_secret(password)})
    for p in (setting_path, creds_path):
        os.chmod(p, 0o600)
    log(f"✓ 远控已注册，凭据已写入 setting.json / credentials.json（workspace: {os.getcwd()}）")


def start_app(appimage, app_args):
    """后台启动 ZCode，等待 relay 就绪。返回 (pid, display_desc)。"""
    CTL_DIR.mkdir(parents=True, exist_ok=True)
    xvfb_run = shutil.which("xvfb-run")
    if xvfb_run and not os.environ.get("ZCODE_USE_SESSION_DISPLAY"):
        prefix = [xvfb_run, "-a", "--server-args=-screen 0 1440x900x24 -nolisten tcp"]
        display_desc = "Xvfb"
    elif os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        prefix = []
        display_desc = "当前会话显示"
    else:
        die("无可用显示: 未找到 xvfb-run 且本会话无 DISPLAY/WAYLAND_DISPLAY。\n"
            "  headless 主机请先安装 Xvfb（Fedora: sudo dnf install xorg-x11-server-Xvfb；Debian: sudo apt install xvfb）")

    env = {**os.environ, "APPIMAGE_EXTRACT_AND_RUN": "1"}
    log_file = APP_LOG.open("w")
    proc = subprocess.Popen(
        [*prefix, str(appimage), *app_args],
        stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        start_new_session=True, env=env)
    log_file.close()
    STATE_FILE.write_text(json.dumps({"pid": proc.pid, "started_at": time.time(),
                                      "appimage": str(appimage), "display": display_desc}))
    return proc.pid, display_desc


def wait_relay_ready(pid, deadline=None):
    """等待官方日志出现 relay waiting_terminal（已连接等待配对）。返回最后观测状态。"""
    deadline = deadline or time.time() + READY_TIMEOUT
    today = lambda: V2_DIR / "logs" / time.strftime("%Y-%m-%d.log", time.localtime())
    seen_size = 0
    if today().exists():
        seen_size = today().stat().st_size  # 只看启动之后的新日志
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return "process-exited"
        f = today()
        if f.exists():
            size = f.stat().st_size
            if size < seen_size:  # 跨天滚动
                seen_size = 0
            if size > seen_size:
                with f.open(errors="replace") as fp:
                    fp.seek(seen_size)
                    new_text = fp.read()
                seen_size = size
                states = re.findall(r'external relay device state \{"state":"([a-z_]+)"\}', new_text)
                if states and states[-1] == "waiting_terminal":
                    return states[-1]
        time.sleep(1)
    return last_relay_state() or "timeout"


def do_start(rotate=False, relogin=False):
    running = find_running()
    if running:
        pid, ver, _ = running[0]
        log(f"ZCode 已在运行 (pid {pid}, v{ver or '?'})")
        print_link(ver)
        return
    # 1) 登录态（BigModel OAuth）
    if relogin or not logged_in():
        if relogin:
            log("执行重新登录 …")
        do_login()
    # 2) 远控设备注册
    if rotate or not relay_registered():
        if rotate:
            log("执行远控重新注册（--rotate）…")
        do_enable()
    # 3) 启动应用
    appimage = find_appimage()
    if not appimage:
        die(f"未找到 AppImage（期望 {APPS_DIR}/ZCode-*-linux-x64.AppImage；"
            f"可先执行 `zcode update` 从官方 manifest 安装）")
    ver = app_version_from_path(appimage)
    # restore 要求开机工作区与远控 context 一致，故用应用原生参数显式打开该工作区
    app_args = ["--no-sandbox", "--disable-gpu"]
    ws = ((read_json(V2_DIR / "setting.json").get("webRemoteControlLastEnabledContext") or {})
          .get("workspacePath") or "")
    if ws and os.path.isdir(ws):
        app_args += ["--open-workspace", ws]
        log(f"将打开远控工作区: {ws}")
    pid, display = start_app(appimage, app_args)
    log(f"ZCode {ver or ''} 启动中 (pid {pid}, {display}, 日志: {APP_LOG}) …")
    state = wait_relay_ready(pid)
    if state == "process-exited":
        tail = ""
        if APP_LOG.exists():
            tail = "\n".join(APP_LOG.read_text(errors="replace").splitlines()[-10:])
        die(f"进程退出。{APP_LOG} 末尾:\n{tail}")
    if state == "waiting_terminal":
        log(f"✓ ZCode v{ver} 已就绪，relay 已连接")
    else:
        log(f"⚠ 已启动，但 {READY_TIMEOUT}s 内未确认 relay 连接（最近状态: {state}）。")
    print_link(ver)


def _kill_pids(pids, sig):
    for pid in pids:
        try:
            pgid = os.getpgid(pid)
        except OSError:
            continue
        try:
            # 只在 pid 是进程组长时用 killpg，避免误伤无关进程组；
            # 自己启动的实例（start_new_session）整组覆盖 xvfb-run/Xvfb/Electron 全树
            (os.killpg if pgid == pid else os.kill)(pgid if pgid == pid else pid, sig)
        except OSError:
            pass


def _descendants(pids):
    """PPid 遍历收集所有后代进程（extract-and-run 的子进程 cmdline 无特征可匹配）。"""
    children = {}
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            m = re.search(r"^PPid:\s*(\d+)$", (d / "status").read_text(), re.M)
        except OSError:
            continue
        if m:
            children.setdefault(int(m.group(1)), []).append(int(d.name))
    out, stack = [], list(pids)
    while stack:
        for child in children.get(stack.pop(), []):
            out.append(child)
            stack.append(child)
    return out


def do_stop(quiet=False):
    running = find_running()
    if not running:
        if not quiet:
            log("ZCode 未在运行")
        return
    pids = [pid for pid, _, _ in running]
    targets = list(dict.fromkeys(pids + _descendants(pids)))
    for sig in (signal.SIGTERM, signal.SIGKILL):
        _kill_pids(targets, sig)
        for _ in range(15):
            if not any(_alive(pid) for pid in targets):
                break
            time.sleep(1)
        if not any(_alive(pid) for pid in targets):
            break
    left = [pid for pid in targets if _alive(pid)]
    if left:
        die(f"部分进程未能退出: {left}")
    STATE_FILE.unlink(missing_ok=True)
    if not quiet:
        log(f"✓ ZCode 已停止（{len(targets)} 个进程）")


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def do_restart():
    do_stop(quiet=True)
    time.sleep(2)
    do_start()


# ---------- 更新 ----------

def fetch_manifest(platform):
    url = (f"{ENDPOINT}/api/v1/releases/electron/manifest"
           f"?platform={platform}&channel=latest")
    req = urllib.request.Request(url, headers={
        "Accept": "application/x-yaml,text/yaml,text/plain,*/*",
        "X-Platform": platform,
        "User-Agent": "zcode-headless-manager"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def parse_manifest(text):
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        die(f"manifest YAML 解析失败: {e}")
    if not isinstance(data, dict) or not isinstance(data.get("version"), str):
        die("manifest 格式异常: 缺少 version")
    entry = {"version": data["version"]}
    for f in data.get("files") or []:
        if isinstance(f, dict) and str(f.get("url", "")).endswith(".AppImage"):
            entry.update(url=f["url"], sha512=f.get("sha512"), size=f.get("size"))
            break
    if "url" not in entry:
        die("manifest 格式异常: 找不到 AppImage 下载项")
    return entry


def ver_tuple(v):
    return tuple(int(x) for x in v.split("."))


def release_platform():
    m = os.uname().machine
    return {"x86_64": "linux-x64", "aarch64": "linux-arm64", "arm64": "linux-arm64"}.get(m, f"linux-{m}")


def download(url, dest, sha512, size):
    log(f"下载 {size / 1e6:.0f} MB …")
    tmp = dest.with_suffix(dest.suffix + ".part")
    urllib.request.urlretrieve(url, tmp)
    h = hashlib.sha512()
    with open(tmp, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if sha512 and h.digest() != base64.b64decode(sha512):
        tmp.unlink(missing_ok=True)
        die("sha512 校验失败")
    if size and tmp.stat().st_size != size:
        tmp.unlink(missing_ok=True)
        die(f"大小不符: {tmp.stat().st_size} != {size}")
    return tmp


def do_update(force=False):
    appimage = find_appimage()
    if appimage:
        cur_ver = app_version_from_path(appimage) or "0"
    else:
        log(f"{APPS_DIR} 下无已安装的 AppImage，将直接安装最新版（desktop 文件等由应用首启自建）")
        cur_ver = "0"
    platform = release_platform()
    log(f"查询最新版本 ({platform}) …")
    entry = parse_manifest(fetch_manifest(platform))
    new_ver = entry["version"]
    if appimage and not force and ver_tuple(new_ver) <= ver_tuple(cur_ver):
        log(f"✓ 已是最新版本 {cur_ver}")
        return
    log(f"发现新版本 {cur_ver} -> {new_ver}")
    log(f"  {entry['url']}")
    tmp = download(entry["url"], APPS_DIR / f"ZCode-{new_ver}-linux-x64.AppImage",
                   entry.get("sha512"), entry.get("size"))
    was_running = bool(find_running())
    if was_running:
        log("停止当前实例 …")
        do_stop(quiet=True)
    APPS_DIR.mkdir(parents=True, exist_ok=True)
    tmp.chmod(0o755)
    final = APPS_DIR / f"ZCode-{new_ver}-linux-x64.AppImage"
    tmp.replace(final)
    for old in APPS_DIR.glob("ZCode-*-linux-x*.AppImage"):
        if old != final:
            old.unlink()
            log(f"  已移除旧版 {old.name}")
    log(f"✓ 已更新到 {new_ver}: {final}")
    if was_running:
        do_start()
    else:
        log(f"执行 `zcode` 可启动并获取远控链接")


def main():
    argv = sys.argv[1:]
    args = [a for a in argv if not a.startswith("-")]
    flags = {a for a in argv if a.startswith("-")}
    cmd = args[0] if args else "start"
    if cmd == "start":
        do_start(rotate="--rotate" in flags, relogin="--relogin" in flags)
    elif cmd == "stop":
        do_stop()
    elif cmd == "restart":
        do_restart()
    elif cmd == "update":
        do_update(force="--force" in flags)
    else:
        die(__doc__ or "未知命令", 2)


if __name__ == "__main__":
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # 管道下游提前关闭（如 | head）时静默退出
    except (AttributeError, ValueError):
        pass
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
