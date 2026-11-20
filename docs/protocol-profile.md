# AiCode 协议映射与运行时说明

本文档说明 `ASGemini2API` 的本地 OAuth 客户端配置要求、Google AiCode 私有 gRPC 协议与 OpenAI Chat Completions 接口映射细节，以及缓存、刷新与冷却机制。OAuth 认证链诊断另见 [`docs/oauth-diagnosis.md`](./oauth-diagnosis.md)。

---

## 1. 运行时配置与 Protobuf 描述符

### 1.1 Desktop 客户端配置与回环参数

- **配置文件路径**：`internal/auth/registration.go` 默认从 `<input-dir>/oauth-client.json`（`--input-dir` 默认 `runtime`，可通过 `ASGEMINI_OAUTH_CLIENT_FILE` 覆盖）加载 Google Desktop（`installed`）客户端 JSON。
- **文件权限要求**：当前有效 UID 拥有的普通文件（非符号链接），权限 `0600`，大小不超过 `16 KiB`。
- **JSON 结构与固定参数**：
  - 仅包含单个 `installed` 对象（含 `*.apps.googleusercontent.com` 的 `client_id` 与非空 `client_secret`），不含 `web` 对象。
  - OAuth 端点、回环主机（`127.0.0.1`）、回调路径（`/CALLBACK_AUTH`）与请求作用域（`https://www.googleapis.com/auth/flexible-api`）由代码固定。
- **回环授权参数（`login`）**：
  - 监听 IPv4 `127.0.0.1:<port>`（支持 `--port 14535` 配合 SSH 端口转发），回调 URI 为 `http://127.0.0.1:<port>/CALLBACK_AUTH`。
  - 发送 `response_type=code`、`state`、`code_challenge`、`code_challenge_method=S256`、`access_type=offline`。
- **未配置或未登录时的行为**：
  - `oauth-client.json` 未配置时，`status` 返回 `logged_in: false` 与 `client_config_error: "oauth_client_not_configured"`；`logout` 直接删除本地 `state/auth_state.json`。
  - `serve` 在缺配置或未登录时仍可启动：`GET /healthz` 返回 `200`，`GET /readyz` 返回 `503 not_ready`，需鉴权的上游路由（`/v1/*`、`/admin/models`、`/admin/quota`）在本地返回 `503 upstream_auth_required`。

### 1.2 预生成 Go Protobuf / gRPC 绑定

`internal/aicode/pb/` 下的 5 个 `.pb.go` 文件由固定 `FileDescriptorSet` 生成并随源码提交。维护脚本 `tools/gen-proto.py` 校验以下三个描述符（改写 Go `go_package` 选项前）的序列化 SHA-256：

| Proto 描述符名称 | 原始 FileDescriptorProto SHA-256 |
| --- | --- |
| `aicode_content.proto` | `d15e728fca091cd664d2956e2e803114a44c8d30ae8843f87d5d0ca352bad515` |
| `management_service.proto` | `fc52ff0b9ccdc804dc29fc0e96d2a8175c0345f33ca7e9dd1c80b28689aa6574` |
| `prediction_service.proto` | `ca32dae31d221cb5de517264190ac6786e4744e55de9d76359296e86c913727b` |

### 1.3 离线发行包开关诊断（`inspect-studio`）

`internal/auth/studio_flags.go` 实现 `asgemini2api inspect-studio --common-jar <PATH>`，核验同 build `AI-262.10968.63.2622.16840690` 的 `android-common.jar`（整包 SHA-256：`7cd8d99a8ccda83172b3747ccc45362cc70899aed3a5e4458fed11bc2af1eab0`）及其 `feature_flags.txt`（条目 SHA-256：`78104148be56fafae71531799d34a6439d0ca313f5e0aef00c35c1d997639da5`），输出 `build`、`channel`、`packaged_defaults`（`use_1p_login_ui`、`enable_fsts`）和 `runtime_observed: false`。

---

## 2. 上游 gRPC 传输与缓存并发合并

- **上游端点**：`aicode.googleapis.com:443`（TLS 1.2+，禁用 gRPC 内置自动重试，单帧最大接收 `16 MiB`）。
- **User-Agent**：`internal/aicode/client.go` 发送 `ASGemini2API/dev (headless; os_type=<os_type>; os_version=<kernel>; arch=<arch>)`。
- **调用的 gRPC 方法**：
  1. `google.gca.aicode.v1.ManagementService/FetchConfig`：
     - `probe` 发送无 `authorization` 元数据的请求，核验 TLS/HTTP2 与 gRPC 连通性。
     - `models`、`verify`、`/v1/models`、`/admin/models` 发送带 `authorization: Bearer <access_token>` 的请求，提取 `available_experiences` 中以 `chat_agent_mode` 开头的条目，按 `model.model_id` 去重，保留 `experience`、`display_name`、`input_token_limit`、`output_token_limit`、`supported_thinking_levels` 与 `supported_features`。
  2. `google.gca.aicode.v1.PredictionService/FetchQuotaStatus`：
     - `quota`、`verify` 与 `/admin/quota` 调用，将上游 `buckets` 映射为 `model_id`、`display_name`、`type`、`remaining_fraction`（`0..1`）和 UTC `reset_time`。
  3. `google.gca.aicode.v1.PredictionService/StreamGenerateContent`：
     - `verify --generate` 与 `POST /v1/chat/completions` 调用。每个网关进程启动时生成一个随机 UUIDv4 作为 `session_id`。
- **目录与配额缓存并发合并（`internal/gateway/catalog.go`）**：
  - `/v1/models`、`/admin/models` 与 `/admin/quota` 的内存缓存使用 singleflight 合并并发拉取，超时上限为 `3*UnaryTimeout + 20s`（默认回退 `65s`）。
  - 单个客户端断开仅递减 `waiters` 计数；全部等待者均取消离开（`waiters == 0`）时才取消底层上游 RPC。

---

## 3. OpenAI Chat Completions 协议映射

### 3.1 Thinking 档位（`reasoning_effort`）

- **请求侧**：
  - AiCode 使用符号枚举 `GenerationConfig.ThinkingConfig.ThinkingLevel`（`MINIMAL`、`LOW`、`MEDIUM`、`HIGH`）。
  - 客户端传入 `reasoning_effort`（支持 `"minimal"`、`"low"`、`"medium"`、`"high"`，大小写不敏感）时，编码器核对该模型的 `supported_thinking_levels`，通过后按符号名映射为 `ThinkingConfig{IncludeThoughts: true, ThinkingLevel: <ENUM>}`（发现枚举与生成配置枚举编号不同，按符号转换）。
  - 模型不支持所请求的档位时返回 HTTP `400 unsupported_parameter`（`param: "reasoning_effort"`）。
- **响应侧**：
  - `Part.thought == true` 的文本在流式 SSE 中输出为 `delta.reasoning_content`，在非流式响应中合并为 `message.reasoning_content`。
  - `usage_metadata.thoughts_token_count` 计入 `usage.completion_tokens`（`candidates_token_count + thoughts_token_count`），并在 `thoughts_token_count > 0` 时填充 `usage.completion_tokens_details.reasoning_tokens`。

### 3.2 结构化输出与函数工具调用

1. **`response_format` 与 `strict` 参数**：
   - `response_format.type` 支持 `"text"`、`"json_object"` 以及（当模型具备 `JSON_SCHEMA_OUTPUT` 特性时）`"json_schema"`。
   - AiCode Protobuf 无服务端严格模式开关。请求在 `response_format.json_schema.strict` 或 `tools[].function.strict` 中显式传入 `strict: true` 时返回 HTTP `400 unsupported_parameter`；`strict: false` 或未设置则允许。
2. **工具声明与选择（`tools` / `tool_choice`）**：
   - 模型特性包含 `FUNCTION_CALLING` 时允许传入 `tools`（`type: "function"`）；同名工具重复声明返回 HTTP `400 invalid_request_error`。函数参数映射至 `FunctionDeclaration.parameters_json_schema`（`google.protobuf.Value`）。
   - `tool_choice` 支持 `"auto"`（`Mode: AUTO`）、`"none"`（`Mode: NONE`）、`"required"`（`Mode: ANY`）以及指定函数对象 `{"type":"function","function":{"name":"..."}}`（`Mode: ANY` + `allowed_function_names`）。
3. **工具调用输出与 ID 校验**：
   - 上游 `Part.function_call` 映射为 `assistant` 消息的 `tool_calls` 条目（`arguments` 为紧凑 JSON 字符串）。上游未分配 `FunctionCall.id` 时，网关生成 UUIDv4 并写回本地历史缓存中的 `pb.Part`。
   - 同一条 `assistant` 消息内出现重复 `tool_call` ID 时立即拒绝（请求侧返回 HTTP `400 invalid_request_error`，上游侧返回 HTTP `502 upstream_error`）。
4. **签名（`thought_signature`）透传与多轮 `tool` 响应配对**：
   - 上游 `Part.thought_signature`（原始字节）以 Base64 编码存入 `extra_content.google.thought_signature`（位于 `tool_calls[i].extra_content` 或 `message.extra_content` / `delta.extra_content`）。
   - 紧跟含 `tool_calls` 的 `assistant` 消息之后，客户端须为每个 `tool_call_id` 提供对应的 `role: "tool"` 消息；编码器将其转换为 `role: "user"` 的 `Part.function_response`（`Id`、`Name`、`Response: {"result": <content>}`）。缺失、重复或 ID 不匹配时返回 HTTP `400 invalid_request_error`。

### 3.3 内存 Sidecar 历史恢复缓存

标准 OpenAI 客户端在下一轮请求中可能丢弃 `reasoning_content` 与 `extra_content.google.thought_signature`。`internal/gateway/history.go` 提供有界内存缓存以还原上游原始 `*pb.Content`：

- **容量与生命周期**：单条轮次上限 `1 MiB`（`historyMaxTurn`），最大 `256` 条（LRU 淘汰），总内存上限 `16 MiB`（`historyLimit`），TTL `2h`（仅驻留内存）。
- **缓存键与多段文本边界**：
  - 缓存键由 `(model.ID, model.Experience, req.User, r.Header.Get("X-Studio-Conversation-Id"))` 与规范化可见对话前缀（`role`、`name`、可见文本、`tool_call_id`、`[id, function.name, parsed_arguments]`）计算带长度前缀的 SHA-256 得到。
  - `role: "user"` 的多段文本数组（`[]ContentPart`）在摘要计算中保留 `[]string` 分段结构，避免 `["a", "b"]` 与 `"a\nb"` 哈希冲突。
  - 一轮生成正常结束（具有合法 `finish_reason`）时存入原始 `*pb.Content`；若不同内容发生前缀冲突则置空该条目。
- **命中恢复与无状态回退**：
  - 下一轮请求命中前缀且 `tool_calls` 数量、ID、函数名完全一致时，直接还原缓存的 `*pb.Content`（保留 `thought` 与 `thought_signature`）。
  - 未命中时回退到基于请求体 `content`、`reasoning_content`、`tool_calls` 与 `extra_content.google.thought_signature` 的无状态编码。

### 3.4 错误响应格式

网关返回的 HTTP 错误体仅包含固定错误码与结构化上游状态元数据（`rpc`、`status`、`reason`、`domain`、`retry_after`），不回显上游原始错误字符串。

---

## 4. 令牌刷新、生成不重放与模型级 429 冷却

### 4.1 令牌刷新与生成单次语义

- **预刷新与过期判定**：
  - 内存 `access_token` 缺失或距过期不超过 `30s`（`refreshMargin = 30s`）时，`auth.Manager.AccessToken` 通过 singleflight 刷新令牌。
  - 上游 gRPC 返回 `UNAUTHENTICATED` 时，仅当 `google.rpc.ErrorInfo` 同时满足 `domain == "googleapis.com"` 且 `reason == "ACCESS_TOKEN_EXPIRED"` 才判定为 `tokenExpired`。
- **只读发现 RPC（`FetchConfig`、`FetchQuotaStatus`）**：
  - 遇到 `UNAVAILABLE` 或 `DEADLINE_EXCEEDED`（无显式 `Retry-After`）时最多执行 1 次 50ms 退避重试。
  - 遇到显式 `ACCESS_TOKEN_EXPIRED` 时触发 1 次 singleflight 刷新并重试 1 次。
- **生成 RPC（`StreamGenerateContent`）**：
  - `verify --generate` 与 `POST /v1/chat/completions` 均禁用自动重试或重放（`grpc.MaxRetryRPCBufferSize(0)`）。若流收到 `ACCESS_TOKEN_EXPIRED`，仅标记当前 access token 失效供下次请求刷新。
- **刷新阶段错误保护**：
  - 刷新返回 `invalid_grant`（HTTP 400/401）或返回 scope 缺少 `aicode` 时，清空本地 `refresh_token` 并标记 `reauth_required: true`。
  - 刷新返回 `invalid_client`、`restricted_client`、`unauthorized_client`、`invalid_scope`、`redirect_uri_mismatch` 等 4xx 客户端错误时，保留磁盘已有 grant，并在当前进程内设置 `refreshBlocked` 阻止重复刷新，直到重启或更新状态文件。

### 4.2 按模型隔离的 429 冷却机制

- 某个模型在 `StreamGenerateContent` 返回 gRPC `RESOURCE_EXHAUSTED` 时，网关返回 HTTP `429`（`code: "upstream_quota_exhausted"`，`type: "rate_limit_error"`），并在内存中记录该 `model.ID` 的冷却截止时间 `modelUntil[modelID]`：
  1. 优先采用上游 `google.rpc.RetryInfo` 或 gRPC trailer `retry-after` 的时长（上限 7 天）；
  2. 若未提供重试时长，且未过期的 `FetchQuotaStatus` 缓存中该模型配额桶 `remaining_fraction == 0` 并带有 `reset_time`，则冷却至 `reset_time`（`30s` 至 `7d`）；
  3. 否则默认冷却 `30s`。
- 冷却窗口内对该模型的后续请求在本地返回 HTTP `429` 与 `Retry-After` 头，其他模型不受影响。
- 上游返回传输层 `UNAVAILABLE` 时设置短时全局冷却（默认 `2s`），返回 HTTP `503 upstream_cooldown`。

### 4.3 CLI `verify` 流程

`asgemini2api verify [--generate [--model ID]]` 校验步骤如下：

1. 调用 `FetchConfig`，要求返回至少一个 `chat_agent_mode*` 模型。
2. 调用 `FetchQuotaStatus`，要求返回至少一个有效配额桶。
3. 默认只读模式下输出 JSON（`verified: true`、`models`、`quota_before`）。
4. 显式传入 `--generate` 时，使用 `--model ID` 或首个发现的模型（对应配额桶 `remaining_fraction == 0` 时直接失败），发送一次 `Reply with only the word OK.`，校验 `finish_reason == "stop"` 且回复 `OK`，随后再次读取 `quota_after` 并输出流帧数与结束原因。
5. 任一步失败均以非零状态码退出，通过 `stage` 区分 `aicode_rpc` 与 `aicode_verification`。
