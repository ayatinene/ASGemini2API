# ASGemini2API

`ASGemini2API` 是基于 Go `1.26.11` 编写的 Linux ARM64 静态编译无头网关（`asgemini2api`）。它从本地配置目录（默认 `runtime/oauth-client.json`）加载与 Android Studio Stable `2026.2.2.9`（Build `AI-262.10968.63.2622.16840690`）一致的 1P Google Desktop（`installed`）客户端配置，请求 `https://www.googleapis.com/auth/flexible-api` 作用域，通过 Google AiCode 私有 gRPC 接口（`aicode.googleapis.com:443`）发现账号可用模型与配额，并在本地提供兼容 OpenAI Chat Completions（`/v1/models`、`/v1/chat/completions`）及管理接口（`/admin/*`）的 HTTP 服务。

## 1. 项目状态（2026-11-20）

项目当前暂停开发。默认仅暴露 `FetchConfig` 中 `chat_agent_mode*` 前缀下的 3 个模型（`gemini-3.6-flash`、`gemini-3.1-pro-preview`、`gemini-3.5-flash-lite`）；`gemini-3-flash-preview` 仅存在于 `chat` 与 `next_edit_prediction` experience，不在默认模型列表中。

**已验证：**
- **本地构建与测试**：通过 `go mod verify`、`go vet ./...`、`go test -race -count=1 ./...`；产出 `linux/arm64` 静态二进制与 `scratch` 容器镜像（`1000:1000`）。对同 build `android-common.jar` 执行 `inspect-studio` 输出 `use_1p_login_ui: true`、`enable_fsts: true`。
- **OAuth 授权与刷新**：同 build 1P 注册 + `flexible-api` scope 真实交互授权通过（旧的非 1P + `aicode` 返回 `403 restricted_client`）。令牌端点将 `flexible-api` 展开为含 `aicode`、`userinfo.email/profile`、`openid` 的第一方 scope 包；`0600` refresh token 持久化与独立进程跨进程刷新通过。
- **管理端与 CLI 登录**：管理端（`GET /admin/oauth` 返回 `200`、未带密钥 `401`、错误 `state` `400`、`POST /admin/oauth/start` 返回 `flexible-api` 链接、`POST /admin/oauth/complete` 换码）与 CLI 回环登录（`/CALLBACK_AUTH` + `state` + S256 PKCE）均已通过。
- **模型发现与配额读取**：`FetchConfig` 返回 6 个 experiences / 4 个模型，网关过滤出 3 个 `chat_agent_mode*` 模型；`FetchQuotaStatus` 返回 4 个 `REQUESTS` 配额桶（第四桶对应 `gemini-3.6-flash`）。
- **生成、流式与工具调用**：`verify --generate` 单次真实生成成功（`finish_reason: stop`，`gemini-3.6-flash` 配额 `1 → 0.999`）。`/v1/chat/completions` 流式文本、非流式/流式工具调用（返回 `finish_reason: tool_calls` 与 `thought_signature`）及带 `tool_call_id` 的多轮工具结果回传均通过。

**尚未验证：**
- 更长多轮会话、上下文逼近窗口上限及内存历史缓存的长期运行表现。
- `gemini-3.1-pro-preview`、`gemini-3.5-flash-lite` 及各 Thinking 档位的逐一生成与扣减比例。
- 不同 Google 订阅层级、账号类别或企业分支（`Baicode`）的服务端行为差异。
- Magpie 或其他外部客户端的实机联调。

---

## 2. 架构与工程参考

### 2.1 目录结构

```text
.
├── cmd/asgemini2api/main.go        # CLI 入口（全局参数、子命令分发、0700 状态目录文件锁、结构化 stage 错误输出）
├── internal/
│   ├── auth/                       # 0600 Desktop 客户端 JSON 加载、Loopback OAuth2+PKCE、0600 原子凭据存储与 inspect-studio 诊断
│   ├── aicode/                     # AiCode gRPC 客户端、TLS 1.2+、User-Agent、错误映射、模型与配额解析
│   │   └── pb/                     # 预生成的 Go Protobuf / gRPC 绑定（静态编入二进制）
│   ├── chat/                       # OpenAI Chat Completions <-> AiCode Protobuf 双向转换、参数与工具 ID 校验
│   ├── gateway/                    # HTTP 路由、Bearer 双密钥鉴权、并发合并缓存、内存历史恢复缓存与模型级 429 冷却
│   └── settings/                   # 环境变量、Go duration 解析、请求体与并发上限、*_KEY / *_KEY_FILE 加载
├── tools/gen-proto.py              # 从 FileDescriptorSet 重新生成 internal/aicode/pb/*.pb.go 的维护脚本
├── Dockerfile                      # Go 1.26.11 编译阶段 + scratch 非 root (1000:1000) 运行时镜像
├── compose.yaml                    # 只读根文件系统、丢弃全部 Capability、127.0.0.1 回环绑定的 Compose 编排
├── .env.example                    # 环境变量与密钥文件挂载示例
└── docs/
    ├── protocol-profile.md         # AiCode 协议映射、缓存合并、Thinking、工具调用、签名恢复与冷却机制
    └── oauth-diagnosis.md          # OAuth 静态差异证据、四层认证模型与 CLI stage 诊断说明
```

### 2.2 工程参考

网关并发控制、流式状态机与容器配置参考了以下提交：

- `https://github.com/lbjlaq/Antigravity-Manager/commit/9b82fb7ef51c42e9d1662a14bd5b718da0525cd8`（令牌 singleflight 刷新、按模型维度隔离配额冷却窗口、OpenAI 流式 `tool_calls` 增量映射与最小运行时容器）
- `https://github.com/Mag1cFall/Antigravity2API/commit/d9614e93633dd48f595fdcc90f7fe9ede0086626`（OAuth2 PKCE 本地回环回调超时管理、原子 `0600` 凭据落盘与并发限制）

---

## 3. 运行时输入与辅助工具

### 3.1 运行时配置文件

Protobuf / gRPC 绑定（`internal/aicode/pb/*.pb.go`）已静态编入二进制。运行时输入目录（`--input-dir` 默认 `runtime`，容器内挂载为 `/inputs:ro`）使用以下文件：

| 默认路径 | 覆盖环境变量 | 权限与格式要求 | 用途 |
| --- | --- | --- | --- |
| `runtime/oauth-client.json` | `ASGEMINI_OAUTH_CLIENT_FILE` | 当前有效 UID 拥有的普通文件（非符号链接），权限 `0600`（`<= 16 KiB`），仅含 `installed`（`client_id`、`client_secret`）且不含 `web` | Google Desktop（`installed`）1P OAuth 客户端 JSON |
| `runtime/api_key` | `ASGEMINI_API_KEY_FILE`（或 `ASGEMINI_API_KEY`） | 普通文件（推荐 `0600`），`24`–`1024` 可见 ASCII 字符，无空白 | `serve` 模式下 `/v1/*` 接口的 Bearer 鉴权密钥 |
| `runtime/admin_key` | `ASGEMINI_ADMIN_KEY_FILE`（或 `ASGEMINI_ADMIN_KEY`） | 普通文件（推荐 `0600`），`24`–`1024` 可见 ASCII 字符，无空白，且与 API Key 不同 | `serve` 模式下 `/admin/*` 接口的 Bearer 鉴权密钥 |

`runtime/` 与 `state/` 已配置在 `.gitignore` 与 `.dockerignore` 中。

### 3.2 离线发行包开关检查（`inspect-studio`）

核验 Android Studio `2026.2.2.9`（Build `AI-262.10968.63.2622.16840690`）打包默认开关时，传入同 build 的 `android-common.jar`（整包 SHA-256：`7cd8d99a8ccda83172b3747ccc45362cc70899aed3a5e4458fed11bc2af1eab0`，内部 `feature_flags.txt` SHA-256：`78104148be56fafae71531799d34a6439d0ca313f5e0aef00c35c1d997639da5`）：

```sh
asgemini2api inspect-studio --common-jar /path/to/pinned/android-common.jar
```

命令输出 `build`、`channel`、`packaged_defaults`（`use_1p_login_ui: true`、`enable_fsts: true`）与 `runtime_observed: false`。详见 [`docs/oauth-diagnosis.md`](./docs/oauth-diagnosis.md)。

### 3.3 Protobuf 绑定重新生成（`tools/gen-proto.py`）

仓库已包含预生成的 `internal/aicode/pb/*.pb.go`。从 `FileDescriptorSet`（`.protoset`）重新生成 Go 绑定可执行：

```sh
python3 tools/gen-proto.py /path/to/aicode_descriptors.protoset \
  --go-plugin protoc-gen-go \
  --grpc-plugin protoc-gen-go-grpc
```

---

## 4. CLI 参考

### 4.1 语法

全局参数 `--input-dir`（默认 `runtime`）与 `--state-dir` 写在子命令之前，子命令参数写在子命令之后：

```text
asgemini2api [--input-dir PATH] [--state-dir PATH] <command> [command flags]
```

### 4.2 子命令

| 子命令 | 子命令参数 | 需要 `oauth-client.json` | 访问网络 | 说明 |
| --- | --- | --- | --- | --- |
| `check-inputs` | 无 | 是 | 否 | 离线校验 Desktop 客户端 JSON 权限与结构，输出 `valid_config`、`client_type: "desktop"`、`requested_scope_count: 1` 及 `google_client_admission: "not_checked"` |
| `inspect-studio` | `--common-jar <PATH>`（必填） | 否 | 否 | 离线核验同 build `android-common.jar` 的 `feature_flags.txt`，输出 `build`、`channel`、`packaged_defaults` 与 `runtime_observed: false` |
| `login` | `--port <0..65535>`（默认 `0`，SSH 转发可用 `14535`）<br>`--timeout <15s..15m>`（默认 `5m`） | 是 | 是 | 在 `127.0.0.1:<port>/CALLBACK_AUTH` 启动回环回调服务（带 `state`、PKCE `S256`、`access_type=offline`），请求 `flexible-api` 并解析 `id_token` 取得账号，输出 `logged_in`、`email` 与 `aicode_access: "not_checked"` |
| `status` | 无 | 可选 | 否 | 离线检查本地 `state/auth_state.json` 会话状态；缺 `oauth-client.json` 时返回 `client_config_error: "oauth_client_not_configured"` |
| `logout` | 无 | 否 | 否 | 删除本地 `state/auth_state.json` |
| `probe` | 无 | 否 | 是 | 向 `aicode.googleapis.com:443` 发送未鉴权 `ManagementService/FetchConfig` RPC，核验 TLS 1.2+ / HTTP/2 连通性 |
| `models` | 无 | 是 | 是 | 调用 `ManagementService/FetchConfig`，输出当前账号下 `chat_agent_mode*` 可用模型、token 上限、Thinking 档位与特性列表 |
| `quota` | 无 | 是 | 是 | 调用 `PredictionService/FetchQuotaStatus`，输出各模型配额桶（`remaining_fraction`、`reset_time`） |
| `verify` | `--generate`（默认 `false`）<br>`--model <ID>`（配合 `--generate`） | 是 | 是 | 默认只读调用 `FetchConfig` 与 `FetchQuotaStatus`，输出 `verified: true` 报告；附加 `--generate` 时执行一次短生成并对比前后配额 |
| `serve` | `--host <IP>`（默认 `127.0.0.1`）<br>`--port <1..65535>`（默认 `8080`） | 可选 | 按需 | 启动 OpenAI 兼容网关与 `/admin/*`；缺配置或未登录时 `/healthz` 返回 `200`、`/readyz` 返回 `503` |
| `healthcheck` | `--url <URL>`（默认 `http://127.0.0.1:8080/healthz`） | 否 | 仅本地 `127.0.0.1` | 校验本地 `/healthz` 是否返回 HTTP 200 |

### 4.3 错误阶段（`stage`）

命令失败时，标准错误输出 `{"error": {"code": "...", "stage": "...", "message": "..."}}`。`stage` 取值包括：`oauth_client_config`、`oauth_client_admission`、`oauth_authorization`、`oauth_code_exchange`、`oauth_account_profile`、`oauth_refresh`、`local_session`、`aicode_rpc`、`aicode_verification`。各阶段说明见 [`docs/oauth-diagnosis.md`](./docs/oauth-diagnosis.md)。

---

## 5. 构建、授权与运行

### 5.1 权限与 UID/GID 规则

- `runtime/oauth-client.json`（或 `ASGEMINI_OAUTH_CLIENT_FILE`）须为当前 UID 拥有的普通文件，权限 `0600`。
- `--state-dir`（或 `ASGEMINI_STATE_DIR`）须为当前 UID 拥有的真实目录，权限 `0700`；目录内的 `.session.lock` 与 `auth_state.json` 权限为 `0600`。
- `Dockerfile` 默认用户为 `1000:1000`。若宿主机 UID/GID 不同，在 `.env` 中设置 `ASGEMINI_UID=$(id -u)` 与 `ASGEMINI_GID=$(id -g)`。
- `serve` 需同时配置互不相同的 API Key 与 Admin Key（`24`–`1024` 可见 ASCII 字符，每个密钥设置 `*_KEY` 或 `*_KEY_FILE` 之一）。

### 5.2 初始化目录与密钥

```sh
cd ASGemini2API

mkdir -p ./runtime ./state
chmod 0700 ./runtime ./state

umask 077
head -c 36 /dev/urandom | base64 | tr -d '\n' > ./runtime/api_key
printf '\n' >> ./runtime/api_key
head -c 36 /dev/urandom | base64 | tr -d '\n' > ./runtime/admin_key
printf '\n' >> ./runtime/admin_key
chmod 0600 ./runtime/api_key ./runtime/admin_key

# 放置 1P Desktop 客户端 JSON 至 ./runtime/oauth-client.json 并设置 0600
chmod 0600 ./runtime/oauth-client.json
```

### 5.3 本地构建与基础检查

```sh
cd ASGemini2API

go mod verify
go vet ./...
go test -count=1 ./...

mkdir -p ./dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" -o ./dist/asgemini2api ./cmd/asgemini2api

./dist/asgemini2api --input-dir ./runtime --state-dir ./state status
./dist/asgemini2api --input-dir ./runtime --state-dir ./state check-inputs
./dist/asgemini2api --input-dir ./runtime --state-dir ./state probe
```

### 5.4 OAuth 授权与验收

管理端控制台会提交 Admin Key 与回调参数，应通过本机回环、SSH 隧道或终止 TLS 的反向代理访问，避免将明文端口暴露到公网。

**方式一：管理端网页控制台（`/admin/oauth`）**

1. 启动 `serve` 后，通过回环或隧道在浏览器打开 `http://127.0.0.1:8080/admin/oauth`。
2. 输入 `ASGEMINI_ADMIN_KEY`，点击“生成授权链接”。
3. 在浏览器打开该链接完成授权。浏览器跳转到无法连接的 `http://127.0.0.1:<port>/CALLBACK_AUTH?code=...&state=...` 属预期现象。
4. 复制地址栏完整回调 URL 粘贴回管理页，点击“完成授权”，服务端校验 `state` 与 PKCE verifier 后写入 `./state/auth_state.json`（`0600`）。

**方式二：CLI 回环登录**

1. 在服务端运行：
   ```sh
   ./dist/asgemini2api --input-dir ./runtime --state-dir ./state login --port 14535 --timeout 5m
   ```
2. 本地电脑建立隧道 `ssh -N -L 14535:127.0.0.1:14535 <user>@<server-host>`，在浏览器打开终端打印的授权链接完成回调。

**授权后验收命令**

```sh
# 查看本地登录状态
./dist/asgemini2api --input-dir ./runtime --state-dir ./state status

# 只读验收（FetchConfig + FetchQuotaStatus）
./dist/asgemini2api --input-dir ./runtime --state-dir ./state verify

# 查询模型列表或配额
./dist/asgemini2api --input-dir ./runtime --state-dir ./state models
./dist/asgemini2api --input-dir ./runtime --state-dir ./state quota

# 单次真实生成并对比前后配额
./dist/asgemini2api --input-dir ./runtime --state-dir ./state verify --generate
```

### 5.5 Docker Compose 部署

1. 生成 `.env`（时间参数使用 Go `time.ParseDuration` 格式，需带 `s`/`m`/`h` 单位）：
   ```sh
   cd ASGemini2API
   cat > .env <<EOF
   ASGEMINI_UID=$(id -u)
   ASGEMINI_GID=$(id -g)
   ASGEMINI_PORT=8080
   ASGEMINI_API_KEY_FILE=/inputs/api_key
   ASGEMINI_ADMIN_KEY_FILE=/inputs/admin_key
   ASGEMINI_UNARY_TIMEOUT=15s
   ASGEMINI_STREAM_TIMEOUT=5m
   ASGEMINI_CATALOG_TTL=24h
   ASGEMINI_QUOTA_TTL=30s
   ASGEMINI_MAX_BODY_BYTES=2097152
   ASGEMINI_MAX_IN_FLIGHT=4
   EOF
   chmod 0600 .env
   ```

2. 构建并启动：
   ```sh
   docker compose -f compose.yaml config -q
   docker compose -f compose.yaml build
   docker compose -f compose.yaml up -d
   ```
   `compose.yaml` 默认绑定 `127.0.0.1:${ASGEMINI_PORT:-8080}:8080`。若在宿主机执行 CLI `login` 或 `logout`，需先停止共享同一 `./state` 目录的 `serve` 容器。

---

## 6. 环境变量与 HTTP 接口

### 6.1 环境变量

| 变量名 | 默认值 | 范围 / 约束 | 说明 |
| --- | --- | --- | --- |
| `ASGEMINI_INPUT_DIR` | `runtime`（容器内 `/inputs`） | 目录路径 | 存放 `oauth-client.json` 与密钥文件的配置目录（低于 `--input-dir`） |
| `ASGEMINI_STATE_DIR` | `$XDG_STATE_HOME/asgemini2api` 或 `~/.local/state/asgemini2api`（容器内 `/state`） | `0700` 同 UID 真实目录 | 存放 `auth_state.json` 与 `.session.lock` 的状态目录（低于 `--state-dir`） |
| `ASGEMINI_OAUTH_CLIENT_FILE` | `<INPUT_DIR>/oauth-client.json` | `0600` 同 UID 普通文件 | 覆盖 Google Desktop（`installed`）客户端 JSON 路径 |
| `ASGEMINI_API_KEY` / `ASGEMINI_API_KEY_FILE` | 无（`serve` 必填其一） | `24`–`1024` 可见 ASCII，无空白 | `/v1/*` 接口的 Bearer 密钥或文件路径 |
| `ASGEMINI_ADMIN_KEY` / `ASGEMINI_ADMIN_KEY_FILE` | 无（`serve` 必填其一） | `24`–`1024` 可见 ASCII，无空白，与 API Key 不同 | `/admin/*` 接口的 Bearer 密钥或文件路径 |
| `ASGEMINI_UNARY_TIMEOUT` | `15s` | `1s`–`2m` | 单次 Unary gRPC（`FetchConfig`、`FetchQuotaStatus`）超时 |
| `ASGEMINI_STREAM_TIMEOUT` | `5m` | `5s`–`30m` | 单次流式生成（`StreamGenerateContent`）总超时 |
| `ASGEMINI_CATALOG_TTL` | `24h` | `30s`–`24h` | 模型目录内存缓存 TTL |
| `ASGEMINI_QUOTA_TTL` | `30s` | `1s`–`10m` | 配额状态内存缓存 TTL |
| `ASGEMINI_MAX_BODY_BYTES` | `2097152`（2 MiB） | `4096`–`16777216` | `/v1/chat/completions` 请求体最大字节数 |
| `ASGEMINI_MAX_IN_FLIGHT` | `4` | `1`–`32` | 最大并发生成流数量（超出返回 HTTP `429 proxy_busy`） |
| `ASGEMINI_LOGIN_REDIRECT_PORT` | `14535` | `1`–`65535` | 管理端发起授权时写入 `redirect_uri` 的回环端口 |

### 6.2 HTTP 端点

| 方法与路径 | 鉴权方式 | 说明 |
| --- | --- | --- |
| `GET /healthz` | 无 | 存活探针，返回 `200 {"status":"ok"}` |
| `GET /readyz` | 无 | 就绪探针，已配置且已登录时返回 `200 {"status":"ready"}`，否则返回 `503 {"status":"not_ready"}` |
| `GET /v1/models` | `Authorization: Bearer <API_KEY>` | OpenAI 兼容模型列表（映射自 `FetchConfig` 的 `chat_agent_mode*` 模型） |
| `GET /v1/models/{id...}` | `Authorization: Bearer <API_KEY>` | 查询单个已发现模型，未找到返回 `404 model_not_found` |
| `POST /v1/chat/completions` | `Authorization: Bearer <API_KEY>` | OpenAI Chat Completions（支持 `stream`、`reasoning_effort`、`tools`/`tool_choice`、`response_format`、`data:` Base64 图片及 `X-Studio-Conversation-Id` 头；显式 `strict: true` 返回 `400 unsupported_parameter`） |
| `GET /admin/oauth` | 无 | 内置授权控制台页面 |
| `POST /admin/oauth/start` | `Authorization: Bearer <ADMIN_KEY>` | 生成或复用未过期的 Google 授权链接，返回 `auth_url`、`redirect_uri`、`expires_in_seconds` |
| `POST /admin/oauth/complete` | `Authorization: Bearer <ADMIN_KEY>` | 接收 `{"callback_url":"..."}` 或裸授权码，校验 `state` 后换码落盘，返回账号状态 |
| `GET /admin/account` | `Authorization: Bearer <ADMIN_KEY>` | 返回本地账号脱敏状态 |
| `GET /admin/models` | `Authorization: Bearer <ADMIN_KEY>` | 返回完整 AiCode 模型元数据与 `fetched_at`；支持 `?refresh=true` |
| `GET /admin/quota` | `Authorization: Bearer <ADMIN_KEY>` | 返回完整配额桶列表与 `fetched_at`；支持 `?refresh=true` |

调用示例：

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz

curl -fsS -H "Authorization: Bearer $(cat ./runtime/admin_key)" \
  http://127.0.0.1:8080/admin/account
curl -fsS -H "Authorization: Bearer $(cat ./runtime/admin_key)" \
  "http://127.0.0.1:8080/admin/models?refresh=true"
curl -fsS -H "Authorization: Bearer $(cat ./runtime/admin_key)" \
  "http://127.0.0.1:8080/admin/quota?refresh=true"

curl -fsS -H "Authorization: Bearer $(cat ./runtime/api_key)" \
  http://127.0.0.1:8080/v1/models
```

协议转换细节见 [`docs/protocol-profile.md`](./docs/protocol-profile.md)。

---

## 7. Magpie 接入参考

按 Magpie 文档（[`yetone/magpie` `docs/reference.md#L352-L378` (`9494a38b`)](https://github.com/yetone/magpie/blob/9494a38b4311cdded517d5ca6846bdcdec43ed28/docs/reference.md#L352-L378)），添加 OpenAI Chat Completions 兼容 Provider 的命令如下：

```sh
magpie provider add 'ASGemini2API' url=http://127.0.0.1:8080/v1 key=<LOCAL_PROXY_API_KEY> id=asgemini2api
```

- **前置就绪**：`magpie provider add` 会立即请求 `GET /v1/models`，执行前需确保 `asgemini2api serve` 已启动且 `/readyz` 返回 `200`。
- **网络可达性**：
  - 同机回环共享网络命名空间时使用 `url=http://127.0.0.1:8080/v1`。
  - 同一自定义 Docker 桥接网络内使用容器 DNS（如 `http://asgemini2api:8080/v1`）。
  - 跨主机调用通过 TLS 反向代理或私有网络（WireGuard / Tailscale / SSH 隧道）转发，避免将明文 HTTP 端口暴露到公网。
- **协议模式**：网关实现 `POST /v1/chat/completions`，添加 Provider 时无需设置 `responses=` 参数。

---

## 8. CI 与镜像构建

`.github/workflows/ci.yml` 包含三个 `linux/arm64`（`ubuntu-24.04-arm`）作业：

1. **`build-and-test`**：使用 Go `1.26.11` 执行 `go mod verify`、`go vet ./...`、`CGO_ENABLED=1 go test -race -count=1 ./...`，编译静态二进制 `dist/asgemini2api`，校验 ELF 静态链接并上传构建产物 `asgemini2api-linux-arm64`。
2. **`docker-image`**：校验 `compose.yaml`，构建 `linux/arm64` `scratch` 镜像 `ghcr.io/ayatinene/asgemini2api:ci`，校验文件白名单并在 `--network none` 下执行 CLI 冒烟测试，上传镜像归档 `asgemini2api-image-linux-arm64`。
3. **`publish-ghcr`**：推送 `v*` 标签且前序作业通过时，将镜像推送到 `ghcr.io/ayatinene/asgemini2api:<vTag>` 与 `ghcr.io/ayatinene/asgemini2api:sha-<8位提交号>`。
