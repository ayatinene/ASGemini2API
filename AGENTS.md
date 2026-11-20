# ASGemini2API 项目约定

## 目标与优先级

将 Android Studio 内置 Gemini 的个人订阅服务实现为无头 API 代理。Google 账号安全、凭据保护和防止代理引入异常行为优先于功能交付。目标只有 Android Studio 的私有 AiCode 协议与个人额度；不以 Gemini 公开 API、Vertex AI 或 Antigravity 的授权、模型或额度代替验收。

## 长期设计原则

1. **以官方客户端实际行为为准。** OAuth 分支与生命周期、客户端身份、gRPC Metadata、请求、模型发现、配额和会话行为，都以当前官方 Android Studio 证据为准。区分打包默认值、运行时值和服务端接受情况；不要凭默认值或其他产品的行为猜测当前配置。将 build、协议和身份配置集中维护，并注明证据。
2. **最小化账号风险。** 避免不一致的身份信息、异常请求模式、无效重试、风暴和不必要的授权或凭据操作。不自动重放可能已被接受的生成；对只读查询使用有界重试，尊重限流与冷却，并传播取消。保持单次协同刷新，不轮转身份来掩盖失败。
3. **参考成熟实现，不照搬协议。** 主动查看 [Antigravity2API](https://github.com/Mag1cFall/Antigravity2API)、[Antigravity-Manager](https://github.com/lbjlaq/Antigravity-Manager) 等项目的实际修复和维护经验。仅复用适用的工程方法；OAuth 参数、Metadata、会话与配额以 Studio 证据为准。
4. **账号安全优先于速度。** 涉及身份、授权、重试、恢复或请求行为的变更，应先核对证据和账号影响，再加回归测试。区分客户端配置、OAuth 流程和用户明确授权的短时凭据验证；不把账号同意等同于服务端已认可某个客户端。凭据只在本地授权路径使用，禁止写入日志、对话、Git、CI 或镜像；不上传原始 JAR、逆向制品或认证状态。
5. **验证目标不变。** 以真实 Studio `FetchConfig`、`FetchQuotaStatus`、`StreamGenerateContent` 结果和额度前后观测为验收依据；协议测试、无鉴权探测及其他产品的成功都不等同于 Studio 账号或额度已验证。分开记录已实现、离线验证与真实验证。
6. **主动定位，不在第一个错误处停工。** 根据失败的具体阶段、HTTP/gRPC 状态、错误详情和已知代码路径排查；修正有证据的偏差，保留仍未知的服务端条件，不盲试或引入未经验证的行为。并行完成不依赖上游授权的工作；只有需要本人登录、获取官方运行时证据或修改现有部署时才请求介入。

## 工程与验收

- 正式项目目录独立于 `android-studio-gemini-research`；研究报告、证据和制品作为只读输入。Git 远端为 `ayatinene/ASGemini2API` 私有仓库，GitHub 操作使用 `ayatinene` 身份。
- 生产运行栈为 Go，目标 Linux ARM64 静态二进制和非 root 容器。以 GitHub Actions 运行构建、竞态测试及镜像检查；不在 CI 使用个人 OAuth 或真实生成。不要修改正在运行的外部服务。
- 改动认证与协议时，覆盖请求构造、scope/PKCE、凭据读写权限、刷新、脱敏、错误、限流、断流取消和签名接续。真实验证使用独立部署、最少必要请求和本地凭据；最后报告实际观察到的结果及未覆盖项。
