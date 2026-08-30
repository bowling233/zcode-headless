# ZCode headless 工具集

在 headless 服务器上使用 ZCode（官方仅发 Electron GUI）。远控走官方 WebUI 中继
`zcode.z.ai`，手机/浏览器打开链接即可操作服务器上的 ZCode。

## 安装

uv tool，从本仓库直接安装，无需 registry：

```bash
uv tool install git+ssh://git@github.com/bowling233/zcode-headless.git
# 或 HTTPS（公开仓库）: uv tool install git+https://github.com/bowling233/zcode-headless.git
# 更新: uv tool upgrade zcode-headless
# 卸载: uv tool uninstall zcode-headless
```

依赖 `uv`（工具环境自动隔离安装 cryptography/pyyaml）；headless 显示依赖 Xvfb
（Debian: `apt install xvfb`，Fedora: `dnf install xorg-x11-server-Xvfb`）。

## 命令

```
zcode              统一入口: 已运行→直接给链接；未登录→交互式 OAuth 登录；
                   未注册远控→注册；然后启动并输出链接
                   （--rotate 重注册远控；--relogin 重新登录）
zcode stop         停止（含 extract-and-run 全进程树）
zcode restart      重启
zcode update       更新最新版（官方 manifest，sha512 校验；--force 重装；
                   未安装时直接引导安装）
```

新机器流程：`zcode update`（下载 AppImage）→ `zcode` → 按提示浏览器登录、
粘贴回调链接 → 自动注册远控 → 输出链接。一条命令到底。

多用户：脚本状态全部按 `$HOME` 隔离（`~/.zcode/`、`~/Applications`），进程
发现按 uid 过滤，各用户实例、凭据、链接互不可见，root 与普通用户可各跑一套。

## 原理要点

- relay 客户端只在 Electron 主进程（app.asar `out/main/index.js`），CLI 引擎
  `zcode.cjs` 里没有，浏览器控制等也在 GUI → 跑完整 AppImage（Xvfb +
  `APPIMAGE_EXTRACT_AND_RUN=1 --no-sandbox --disable-gpu`）。
- 链接四参数全部持久化、可离线重建：
  `sid` ← `setting.json:webRemoteControlExternalRelayDevice.deviceSid`；
  `hash` ← `credentials.json` key `web-remote-control:external-relay:pass_hash`
  （`enc:v1` = AES-256-GCM，key = sha256(`zcode-credential-fallback:linux:$HOME:$USER`)，
  格式 `enc:v1:nonce_b64url.tag_b64url.ct_b64url`）；`mid` ←
  `telemetry-state.json:deviceMid`；`t` = 现生成毫秒时间戳。
- relay 是设备级信任（只认 pass_hash），注册无需账号 token。握手：
  `device_register_init{device_mid,pass_hash,meta}` → `device_register_ack{device_sid}`
  → `auth_init{role:"device"}` → `auth_challenge{nonce}` →
  `auth_response{proof=base64url(HMAC-SHA256(pass_hash,"nonce|device|sid"))}`
  → `auth_ack{pair_status:"waiting"}`。端点 `wss://zcode.z.ai/ws`。
- relay 会回收无活跃连接的未配对设备 → 注册后不必保活；应用首连若
  `AUTH_FAILED` 会 rotate 自愈（同一 pass_hash 重新注册、覆盖持久化），
  实测确认有效。
- 应用启动的 relay 自动恢复（`restorePreviouslyEnabled`）要求开机工作区与
  `webRemoteControlLastEnabledContext.workspacePath` 一致，否则静默跳过 →
  `start` 会带 `--open-workspace <path>`（应用原生参数）打开同一工作区。
- 更新通道：`GET {ENDPOINT}/api/v1/releases/electron/manifest?platform=linux-x64&channel=latest`
  （YAML：version + files[].url/sha512/size，AppImage 直链）。

## 大版本更新后的回归清单

1. `zcode update`：版本比对、下载校验、替换；无已装版本时直接引导安装
   （desktop 文件由应用首启自建并维护，脚本不管）。
2. `zcode stop && zcode`：启动 → `waiting_terminal` 日志 → 链接产出；手机打开可用。
3. `zcode`（已运行时进程可见性、sid 一致性、链接产出）。
4. 若失效，拆新版 AppImage 的 `resources/app.asar`（提取器见研究目录）重点核对：
   链接构造 `buildWebRemoteControlExternalQrUrl`、注册握手消息、
   `restorePreviouslyEnabled` 条件、manifest 端点、`enc:v1` 派生密钥、
   setting/credentials 的 key 名。协议无文档，以 bundle 为准。

## 踩坑记录

- **restore 静默跳过**：工作区不匹配时没有任何日志，症状是启动成功但
  v2 日志零 relay 记录 → 检查 `--open-workspace` 是否带上。
- **extract-and-run 进程隐形**：真实 Electron 在 `/tmp/appimage_extracted_*/`，
  cmdline 不含 AppImage 路径；进程匹配须含该模式，否则 stop 杀不净
  （Electron 成孤儿）、status 误报。stop 用进程组 killpg（仅组长）+ PPID 树扫。
- **单实例锁会向存活实例转发 argv**（second-instance），可能歪打正着触发
  restore；不要依赖，但排查怪象时要想到。
- **撞名**：ZCode 运行时把挂载目录加进子进程 PATH，内有同名 `zcode`（Electron
  二进制）。从 ZCode 会话内部裸敲 `zcode` 可能拉起 GUI（单实例锁会使其自退）；
  拿不准用绝对路径。
- **v2 日志含 NUL**（多写者残留）：grep 要加 `-a`。
- relay 日志在 `~/.zcode/v2/logs/YYYY-MM-DD.log`，就绪标记
  `external relay device state {"state":"waiting_terminal"}`；
  启动器自身日志在 `~/.zcode/headless/app.log`。
- `hash` 即配对凭据，链接勿外传；泄漏时 `zcode --rotate` 换绑。
