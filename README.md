# ZCode headless 工具集

在 headless 服务器上使用 ZCode（官方仅发 Electron GUI）。远控走官方 WebUI 中继
`zcode.z.ai`，手机/浏览器打开链接即可操作服务器上的 ZCode。

> **3.16.0 起远控协议切换为 Relay V2（账号绑定）**：注册改为带登录 JWT 的纯 HTTP
> 调用，链接不再携带 `hash` 秘密参数，手机浏览器打开链接后需登录同一账号才能配对。
> 本工具按 AppImage 版本自动选择 V2（≥3.16.0）/ V1（3.4.0~3.15.x）协议。

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
AppImage 解压目录固定隔离在 `~/.zcode/headless/tmp/`，不会与其他用户或 root 在
`/tmp/appimage_extracted_*` 下的同名目录冲突。

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

### Relay V2（ZCode ≥ 3.16.0，当前）

- 注册是账号绑定的纯 HTTP（无需 WebSocket 握手），JWT 取自登录凭据
  `credentials.json:zcodejwttoken`，userId 取自
  `oauth:{active_provider}:user_info` 的 `id`/`user_id`（与官方
  `createTelemetryAuthorizationLoader` 同源）：
  `POST {origin}/api/v1/remote/device {"device_mid":mid}`（Bearer JWT）→ `device_sid`。
- 设备身份持久化在 `setting.json:webRemoteControlRelayV2Device`
  = `{deviceSid, userId, endpointOrigin}`；应用核对 userId/endpointOrigin 一致
  即复用该 SID，否则自动重注册并回写（应用侧 `AUTH_FAILED` 也会强制重注册自愈）。
- 应用启动后自行 `POST /api/v1/remote/token {role:"device"}` 取一次性 token 连
  `wss://{origin}/api/v1/remote/ws2` 完成 `auth_init`（meta 上报主机名/平台/版本），
  本工具不参与数据面。
- 链接只带路由提示，无秘密参数：
  `{origin}/remote/v4?sid=…&mid=…&name=…&app_version=…`。
  手机浏览器打开后必须**登录同一账号**（V2 按账号隔离设备）；带 `hash`/`t` 的
  旧 V1 链接会被页面拒绝（invalid-mobile-connection）。
- 就绪日志（主日志 `~/.zcode/v2/logs/YYYY-MM-DD.log`）：
  `[web-remote-control] V2 device state {"state":"waiting_terminal"}`。
- 3.16+ 应用首次启动远控时会主动清除 V1 的
  `webRemoteControlExternalRelayDevice` 设置与 `pass_hash` 凭据；本工具注册 V2
  时也会顺手清理这两个旧 key。

### Relay V1（ZCode 3.4.0 ~ 3.15.x，保留兼容）

- relay 客户端只在 Electron 主进程（app.asar `out/main/index.js`），CLI 引擎
  `zcode.cjs` 里没有，浏览器控制等也在 GUI → 跑完整 AppImage（Xvfb +
  `APPIMAGE_EXTRACT_AND_RUN=1 --no-sandbox --disable-gpu`）。
- 链接四参数全部持久化、可离线重建：
  `sid` ← `setting.json:webRemoteControlExternalRelayDevice.deviceSid`；
  `hash` ← `credentials.json` key `web-remote-control:external-relay:pass_hash`
  （`enc:v1` = AES-256-GCM，key = sha256(`zcode-credential-fallback:linux:$HOME:$USER`)，
  设置 `ZCODE_CREDENTIAL_SECRET` 时与官方一样优先使用该值；格式
  `enc:v1:nonce_b64url.tag_b64url.ct_b64url`）；`mid` ←
  `telemetry-state.json:deviceMid`；`t` = 现生成毫秒时间戳。
- `hash` 的明文值是 `base64(sha256(randomPassword))`，不是随机密码本身；注册、
  HMAC proof、凭据持久化和远控链接统一使用这个 pass hash，与 3.14.3 官方包一致。
- relay 是设备级信任（只认 pass_hash），注册无需账号 token。握手：
  `device_register_init{device_mid,pass_hash,meta}` → `device_register_ack{device_sid}`
  → `auth_init{role:"device"}` → `auth_challenge{nonce}` →
  `auth_response{proof=base64url(HMAC-SHA256(pass_hash,"nonce|device|sid"))}`
  → `auth_ack{pair_status:"waiting"}`。端点 `wss://zcode.z.ai/ws`。
- relay 会回收无活跃连接的未配对设备 → 注册后不必保活。

### 通用

- 应用启动的 relay 自动恢复（`restorePreviouslyEnabled`）要求开机工作区与
  `webRemoteControlLastEnabledContext.workspacePath` 一致，否则静默跳过 →
  `start` 会带 `--open-workspace <path>`（应用原生参数）打开同一工作区。
- 更新通道：`GET {ENDPOINT}/api/v1/releases/electron/manifest?platform=linux-{arch}&channel=latest`
  （YAML：version + files[].url/sha512/size，AppImage 直链）。
- 远控页面版本与官方门槛一致：ZCode 3.4.0 stable 起使用 `/remote/v4`，更早版本
  使用 `/remote/v3`。

## 与开源版 ZCode 的关系

ZCode 3.16.x 的公开源码已包含 Relay V2 完整实现
（`packages/desktop/src/main/web-remote-relay/`、
`packages/shared/src/web-remote-relay/` 与
`docs/web-remote-control/relay-v2-pairing.md` 规范），本工具的 V2 注册/链接逻辑
即对齐该源码。更早版本（3.14/3.15）的 external relay 实现未开源，回归协议时以
实际 AppImage 的 `resources/app.asar/out/main/index.js` 为准。

公开源码中的 `zcode-server-cli` 当前只在 loopback 上提供独立 Agent Server，供本机
或 SSH 隧道连接；它没有启动中心 external relay，也不生成 `zcode.z.ai/remote/v4`
链接，所以暂时不能取代本工具的 Electron + Xvfb 启动路径。

## 大版本更新后的回归清单

1. `zcode update`：版本比对、下载校验、替换；无已装版本时直接引导安装
   （desktop 文件由应用首启自建并维护，脚本不管）。
2. `zcode stop && zcode`：启动 → 就绪日志 → 链接产出；手机打开可用
   （V2 需登录同一账号）。
3. `zcode`（已运行时进程可见性、sid 一致性、链接产出）。
4. 若失效，优先核对公开源码（`zai-org/ZCode`）的
   `web-remote-relay` 模块与 `relay-v2-pairing.md`；未开源部分再拆 AppImage 的
   `resources/app.asar` 核对：链接构造 `buildWebRemoteControlExternalQrUrl`、
   注册握手消息、`restorePreviouslyEnabled` 条件、manifest 端点、`enc:v1` 派生
   密钥、setting/credentials 的 key 名。

## 踩坑记录

- **setting.json 不得写 null 清 key**：应用用 zod 校验整个文件，`optional` 只接受
  key 缺省，`null` 会让校验失败 → 应用回退默认设置 → 远控恢复静默失效、身份
  被后续写盘冲掉。清理旧 key 必须整键移除（`_remove_json_keys`）。
- **就绪等待不能回看旧状态**：等待超时时兜底读"今天日志最后一条状态"会把上
  一个实例遗留的 `waiting_terminal` 误报成本次就绪；只统计本次启动 checkpoint
  之后新写出的状态行。
- **3.16.2 升级后拿不到链接（Relay V2 切换）**：旧版工具盯的 V1 就绪日志
  `external relay device state` 不再出现（新格式 `V2 device state`），且 V1
  `pass_hash` 被应用启动时清除、旧 `hash` 链接被页面拒绝 → 症状是启动后
  等待超时、无链接。0.3.0 起按版本自动走 V2。
- **restore 静默跳过**：工作区不匹配时没有任何日志，症状是启动成功但
  v2 日志零 relay 记录 → 检查 `--open-workspace` 是否带上。
- **AppImage 临时目录跨用户冲突**：extract-and-run 默认在 `/tmp` 使用内容哈希命名
  固定目录；同一版本若曾由 root 启动并残留 0700 目录，普通用户会报
  `Failed to extract AppImage`。启动器强制使用 `~/.zcode/headless/tmp/` 避免冲突。
- **就绪日志竞态**：必须在拉起应用前记录日志 offset，并同时接受
  `waiting_terminal` 与 `paired`；否则应用快速就绪或手机快速配对时会无谓等待超时。
- **extract-and-run 进程隐形**：真实 Electron 在 `$TMPDIR/appimage_extracted_*/`，
  cmdline 不含 AppImage 路径；进程匹配须含该模式，否则 stop 杀不净
  （Electron 成孤儿）、status 误报。stop 用进程组 killpg（仅组长）+ PPID 树扫。
- **单实例锁会向存活实例转发 argv**（second-instance），可能歪打正着触发
  restore；不要依赖，但排查怪象时要想到。
- **撞名**：ZCode 运行时把挂载目录加进子进程 PATH，内有同名 `zcode`（Electron
  二进制）。从 ZCode 会话内部裸敲 `zcode` 可能拉起 GUI（单实例锁会使其自退）；
  拿不准用绝对路径。
- **v2 日志含 NUL**（多写者残留）：grep 要加 `-a`。
- relay 日志在 `~/.zcode/v2/logs/YYYY-MM-DD.log`，就绪标记
  V2: `[web-remote-control] V2 device state {"state":"waiting_terminal"}`，
  V1: `external relay device state {"state":"waiting_terminal"}`；
  启动器自身日志在 `~/.zcode/headless/app.log`。
- V1 的 `hash` 即配对凭据，链接勿外传；泄漏时 `zcode --rotate` 换绑。
  V2 链接无秘密，但 sid 关联账号设备列表，同样不宜外传。
