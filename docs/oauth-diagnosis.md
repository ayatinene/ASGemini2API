# OAuth 认证链诊断与验收结论

本文档记录 `ASGemini2API` 针对 Android Studio Stable `2026.2.2.9`（Build `AI-262.10968.63.2622.16840690`）的 OAuth 静态证据、四层认证模型与 CLI 错误阶段定义。

---

## 1. 实测结论（2026-11-20）

- **客户端注册与 Scope**：同 build 1P Desktop（`installed`）客户端注册 + `OAuthScope.Flexible`（`https://www.googleapis.com/auth/flexible-api`），回环回调路径 `/CALLBACK_AUTH`，PKCE `S256`。
- **准入对比**：Google 授权页对该组合正常发放授权码；旧组合（非 1P + `https://www.googleapis.com/auth/aicode`）返回 `403 restricted_client`。
- **Scope 展开**：令牌端点将 `flexible-api` 展开为第一方 scope 包（实测含 `aicode`、`userinfo.email`、`userinfo.profile`、`openid`、`androidpublisher`、`experimentsandconfigs`、`cclog` 等），不原样回显 `flexible-api`。本地按展开集合包含 `aicode` 判定满足 `Flexible`，并以 `0600` 权限持久化 refresh token。
- **线上验收**：`verify` 只读通过（3 个 `chat_agent_mode*` 模型、4 个配额桶）；`verify --generate` 成功（`finish_reason: stop`，`gemini-3.6-flash` 配额 `1 → 0.999`）；网关流式文本、非流式/流式工具调用与工具结果回传均通过。管理端授权控制台与 API 实测通过（页面 `200`、无密钥 `401`、错误 `state` `400`、`start` 返回 `flexible-api` scope）。

---

## 2. 静态差异证据：1P + `flexible-api` 与非 1P + `aicode`

1. **非 1P + `aicode` 的拒绝现象**：
   - 使用 `StudioClientInfo.secretWithout1pFlow` 与 `AiCodeLoginFeature` 的 `https://www.googleapis.com/auth/aicode` 发起授权时，Google 授权页返回 `403 restricted_client`（`Unregistered scope(s) in the request: https://www.googleapis.com/auth/aicode`）。
2. **构造器默认值 vs. 发行包配置**：
   - `BooleanFlag` 构造器中的 `google.login.use.1p.login.ui=false` 与 `google.login.enable.fsts=false` 是无配置源时的回退值。
   - 同 build `AI-262.10968.63.2622.16840690` 的 `android-common.jar`（整包 SHA-256：`7cd8d99a8ccda83172b3747ccc45362cc70899aed3a5e4458fed11bc2af1eab0`）内，`feature_flags.txt`（SHA-256：`78104148be56fafae71531799d34a6439d0ca313f5e0aef00c35c1d997639da5`）第 73、76 行均设为 `COMPLETE`。
   - `FeatureConfigurationProvider.getValueById` 按 `currentLevel <= flagLevel` 判定，Stable 渠道对 `COMPLETE` 级别默认启用。
3. **调用链分支**：
   - `StudioClientInfo.<init>`（`call-chain-steps.tsv:18-24`）根据 1P 开关选择客户端注册并存入 `loginSecrets`。
   - `GoogleLoginState$Companion.loginAndCreate`（`call-chain-steps.tsv:34-37`）在 FST 开启时请求 `OAuthScope.Flexible`（`https://www.googleapis.com/auth/flexible-api`），否则按启用特性合并 feature scopes。
   - 开关解析优先级依次为：IDE 用户设置 → JVM 属性 → 缓存的服务端开关 → 发行包级别 → 构造器默认值（`StudioFlags.createFlags`、`Flags.getValue`）。

---

## 3. IDE 登录与 AiCode 访问的四层模型

| 层 | 官方 IDE 静态证据 | 已验证结果与未验证项 |
| --- | --- | --- |
| **OAuth 客户端注册** | `StudioClientInfo` 根据 1P 开关选择注册；FST 开关决定请求 `Flexible` 或按功能合并 scope。 | 已验证：同 build 1P 注册 + `flexible-api` 在授权页正常准入并发放授权码；非 1P + `aicode` 返回 `restricted_client`。 |
| **用户授权与回调** | 使用外部浏览器、回环回调 `/CALLBACK_AUTH` 与 S256 PKCE。网关额外发送 `state` 与 `access_type=offline`。 | 已验证：CLI 回环回调、`state` 校验、PKCE 换码以及管理端（`GET /admin/oauth`、`POST /admin/oauth/start`、`POST /admin/oauth/complete`）均通过。 |
| **Token 交换与生命周期** | 用同一 PKCE 实例生成 challenge/verifier，按持久化的 client flow 恢复和刷新；FST 开启时可共享已登录状态。 | 已验证：换码成功，`flexible-api` 展开含 `aicode`，refresh token 以 `0600` 持久化，独立进程凭 refresh token 刷新取得 access token。 |
| **AiCode gRPC 与配额** | 将活动账号 access token 作为 Bearer 发送，查询模型与配额。 | 已验证：`FetchConfig` 返回 3 个 `chat_agent_mode*` 模型，`FetchQuotaStatus` 返回 4 个配额桶，单次生成配额 `1 → 0.999`，流式与工具调用通过。<br>尚未验证：长会话、其余模型/Thinking 档位逐一生成与不同订阅层级差异。 |

---

## 4. 离线诊断命令与 CLI 错误阶段（`stage`）

### 4.1 离线检查命令

- **`check-inputs`**：
  - 离线校验 `--input-dir`（默认 `runtime`）下的 `runtime/oauth-client.json`（或 `ASGEMINI_OAUTH_CLIENT_FILE`）是否为 `0600` 同 UID 普通文件且符合 Google Desktop（`installed`）JSON 结构。
  - 输出 `{"valid_config":true,"client_type":"desktop","requested_scope_count":1,"google_client_admission":"not_checked"}`。
- **`inspect-studio --common-jar <PATH>`**：
  - 离线核验同 build `AI-262.10968.63.2622.16840690` 的 `android-common.jar` 及其 `feature_flags.txt` 哈希与开关默认值：
    ```json
    {
      "build": "AI-262.10968.63.2622.16840690",
      "channel": "stable",
      "packaged_defaults": {
        "use_1p_login_ui": true,
        "enable_fsts": true
      },
      "runtime_observed": false
    }
    ```

### 4.2 CLI 错误阶段（`stage`）

CLI 在标准错误输出 JSON 中通过 `error.stage` 标识错误阶段：

| `stage` 值 | 触发阶段与含义 |
| --- | --- |
| `oauth_client_config` | 本地 `oauth-client.json` 缺失（`oauth_client_not_configured`）、权限/符号链接不合规（`insecure_oauth_client_file`）或 JSON 结构无效（`invalid_oauth_client_file`） |
| `oauth_client_admission` | 浏览器授权回调返回客户端或作用域拒绝（`restricted_client`、`invalid_client`、`unauthorized_client`、`invalid_scope`、`redirect_uri_mismatch`） |
| `oauth_authorization` | 浏览器交互授权取消、失败或超时（若浏览器停留在错误页未跳回本地回调，CLI 超时报 `code: "timeout"`） |
| `oauth_code_exchange` | 已收到回调 `code`，但换取令牌失败，或返回的 scope 集合缺少 `aicode` |
| `oauth_account_profile` | 解析令牌端点返回的 `id_token`（或回退调用 Google Userinfo 端点）校验已验证邮箱失败 |
| `oauth_refresh` | 使用持久化 `refresh_token` 刷新访问令牌失败（遇到 `invalid_client` 等 4xx 客户端拒绝时保留磁盘已有 grant，并在进程内标记 `refreshBlocked` 阻止重复刷新） |
| `local_session` | 本地 `state/auth_state.json` 缺失、需重新授权（`reauth_required`）、文件损坏或 `0700`/`0600` 权限校验失败 |
| `aicode_rpc` | 上游 `aicode.googleapis.com:443` gRPC 调用返回错误（含 `code`、`rpc` 及可选 `reason`、`domain`、`retry_after_seconds`） |
| `aicode_verification` | RPC 返回成功状态，但响应未包含真实 `chat_agent_mode*` 模型或可读配额桶 |
