# ASGemini2API 交接文档（2026-11-20）

当前状态：项目在分支 `implementation/headless` 暂停开发，已完成真实 OAuth 授权、跨进程 refresh token 刷新、只读 `verify`、单次真实生成及网关流式与工具调用验收。

## 1. 目标 Android Studio 版本与 1P + `flexible-api` 依据

- **目标版本与构建号**：Android Studio Rabbit 2 | 2026.2.2 Patch 1（`2026.2.2.9` Stable，Build `AI-262.10968.63.2622.16840690`）。
- **打包默认分支依据**：
  - 同 build 官方 `android-common.jar`（整包 SHA-256：`7cd8d99a8ccda83172b3747ccc45362cc70899aed3a5e4458fed11bc2af1eab0`）内的 `feature_flags.txt`（SHA-256：`78104148be56fafae71531799d34a6439d0ca313f5e0aef00c35c1d997639da5`）第 73、76 行将 `google.login.use.1p.login.ui` 与 `google.login.enable.fsts` 设为 `COMPLETE`（`BooleanFlag` 构造器中的 `false` 为无配置源时的默认值）。
  - `FeatureConfigurationProvider.getValueById` 按 `currentLevel <= flagLevel` 判定，Stable 渠道对 `COMPLETE` 默认启用；`asgemini2api inspect-studio --common-jar <PATH>` 输出两项 `packaged_defaults` 均为 `true`（`runtime_observed: false`）。
  - 对应 `android.jar` 中的 `StudioClientInfo.<init>` 选择 1P `installed` 客户端注册，`GoogleLoginState$Companion.loginAndCreate` 在 FST 启用时请求 `OAuthScope.Flexible`（`https://www.googleapis.com/auth/flexible-api`）。

## 2. 已验证能力

| 模块 | 实测结果 |
| --- | --- |
| 客户端注册与准入 | 同 build 1P `installed` 客户端注册 + `https://www.googleapis.com/auth/flexible-api` 在 Google 授权页正常准入；旧的非 1P + `aicode` 返回 `403 restricted_client`。 |
| 授权、换码与展开 Scope | 回环 `127.0.0.1:<port>/CALLBACK_AUTH` + `state` + S256 PKCE 完成交互授权。令牌端点将 `flexible-api` 展开为第一方 scope 包（含 `aicode`、`userinfo.email/profile`、`openid` 等）；本地按展开包含 `aicode` 判定满足 `Flexible` 并持久化 `0600` refresh token。 |
| 账号身份解析 | 解析令牌端点返回的 `id_token`（校验 `iss`、`aud`、`email_verified`），`userinfo` 作为回退。 |
| 跨进程刷新与只读验收 | 独立进程凭持久化 refresh token 刷新取得 access token。`verify` 只读通过，返回 3 个 `chat_agent_mode*` 模型与 4 个配额桶。 |
| 单次生成与扣减 | `verify --generate` 返回 `finish_reason: stop`，`gemini-3.6-flash` 配额桶 `remaining_fraction` 由 `1` 变为 `0.999`。 |
| 网关流式与工具调用 | `/v1/chat/completions` 流式文本、非流式/流式工具调用均通过：工具调用返回 `finish_reason: tool_calls`，参数与 `thought_signature` 正确；带 `tool_call_id` 与工具结果的多轮请求正常返回文本。 |
| 管理端授权控制台 | `GET /admin/oauth`（返回 `200`）、未带密钥访问 API（返回 `401`）、错误 `state`（返回 `400`）、`POST /admin/oauth/start`（返回含 `flexible-api` 的授权链接）与 `POST /admin/oauth/complete` 换码均已通过。 |

## 3. 模型与配额桶对应关系

1. **上游 6 个 `available_experiences` 与 4 个模型**：
   - **3 个 `chat_agent_mode*` 模型（网关默认暴露）**：经 `internal/aicode/discovery.go` 按 `chat_agent_mode` 前缀过滤并按 `model.model_id` 去重后得到 `gemini-3.6-flash`、`gemini-3.1-pro-preview`、`gemini-3.5-flash-lite`。
   - **1 个非 `chat_agent_mode*` 模型**：`gemini-3-flash-preview` 仅存在于 `chat` 与 `next_edit_prediction` experience 中。
2. **上游 4 个配额桶（`FetchQuotaStatusResponse.buckets`）**：
   - 返回 4 个 `REQUESTS` 配额桶，分别对应 `gemini-3.1-pro-preview`、`gemini-3.5-flash-lite`、`gemini-3-flash-preview` 与第四桶 `gemini-3.6-flash`。
   - `verify --generate` 单次生成后，`gemini-3.6-flash` 配额桶由 `1` 变为 `0.999`。

## 4. 管理端授权实现要点

- `auth` 包提供 `BeginLogin`、`ParseCallback`、`CompleteLogin`，由 CLI `login` 与管理端 `/admin/oauth/*` 共用。
- `ASGEMINI_LOGIN_REDIRECT_PORT`（默认 `14535`）设置 `redirect_uri` 端口；浏览器授权后跳转到 `http://127.0.0.1:<port>/CALLBACK_AUTH`，复制该 URL 到 `/admin/oauth` 即可完成换码。
- 回调 URL 校验要求 scheme/host/port/path 与本次 `redirect_uri` 完全一致，且 `state`、`code` 各恰好一个。
- 登录成功时递增会话代次并清空模型缓存、配额缓存、429 冷却与历史签名缓存；旧账号在途刷新不会覆盖新会话。

## 5. 恢复开发入口

- **网关代码与文档（`/workspace/Gemini/ASGemini2API`）**：
  - `internal/auth/auth.go`：OAuth2 + PKCE 流程、`flexible-api` 展开 scope 校验、`id_token` 解析、`30s` 预刷新与 `refreshBlocked` 保护。
  - `internal/aicode/discovery.go`：`ChatAgentExperiencePrefix`（`"chat_agent_mode"`）模型过滤与去重、Thinking 档位映射、`FetchQuotaStatus` 配额桶解析。
  - `internal/gateway/oauth_admin.go`：`/admin/oauth`、`/admin/oauth/start`、`/admin/oauth/complete` 与内存授权会话管理。
  - `cmd/asgemini2api/verify.go`：只读 `verify` 与 `--generate` 前后配额对比。
  - `docs/oauth-diagnosis.md` 与 `docs/protocol-profile.md`：OAuth 认证诊断与 AiCode 协议映射细则。
- **逆向证据与复核工具（`/workspace/Gemini/android-studio-gemini-research`）**：
  - `README.md`、`OAUTH-CHAIN.md`、`PRIVATE-RPC.md`、`PROTOCOL.md`、`COMPATIBILITY.md` 及 `tools/verify_oauth_chain.py`。

## 6. 重建、授权与运行命令

准备 `runtime/oauth-client.json`、`runtime/api_key`、`runtime/admin_key`（均 `0600`）与 `state/`（`0700`）后执行：

```sh
cd /workspace/Gemini/ASGemini2API

# 1. 构建 Linux ARM64 静态二进制
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" -o ./dist/asgemini2api ./cmd/asgemini2api

# 2A. CLI 回环授权（配合本地浏览器或 SSH 端口转发 14535）
./dist/asgemini2api --input-dir ./runtime --state-dir ./state login --port 14535 --timeout 5m

# 2B. 启动 serve 并通过 http://127.0.0.1:8080/admin/oauth 完成授权
ASGEMINI_API_KEY_FILE=./runtime/api_key \
ASGEMINI_ADMIN_KEY_FILE=./runtime/admin_key \
  ./dist/asgemini2api --input-dir ./runtime --state-dir ./state serve --host 127.0.0.1 --port 8080

# 3. 只读验收
./dist/asgemini2api --input-dir ./runtime --state-dir ./state verify
```

access token 在进程内缓存，进程重启后由 `state/auth_state.json` 中的 refresh token 自动刷新。

## 7. 未验证项

- 尚未验证：多轮长上下文会话、接近输入 token 上限及进程内 Sidecar 历史缓存（TTL/LRU）在长时间运行下的表现。
- 尚未验证：`gemini-3.1-pro-preview`、`gemini-3.5-flash-lite` 及各 Thinking 档位的逐一真实生成与配额扣减比例。
- 尚未验证：不同 Google One AI 套餐层级、非 Consumer 账号及企业分支（`Baicode` / `google.cloud.businessaicode.v1beta`）的服务端行为。
- 尚未验证：Magpie 或其他外部客户端的实机注册与联调。
- 尚未验证：换号瞬间若有切换前已进入模型目录阶段的并发生成请求，可能以新凭据提交旧目录选出的模型。
