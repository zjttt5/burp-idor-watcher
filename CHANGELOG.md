# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-11

首个可用版本。

### 新增
- 被动观察：基于 `ProxyResponseHandler` 监听 Proxy 流量，不修改任何报文
- 路径与参数模板归一化（数字段 / 十六进制段 / UUID 段 / 资源 ID 类查询参数）
- 按模板聚合多资源 ID，记录状态码、响应长度、响应体哈希
- 三重判据被动标记：疑似越权候选 / 参数未生效（响应恒等） / 存在权限边界
- 双身份重放：替换 Cookie 后经 `api.http().sendRequest()` 重发并对照
- 重放判定：响应完全一致 / 响应近似（<2%） / 两侧响应不同 / 被拒绝
- SuiteTab 表格 UI、CSV 导出、自动落盘
- 身份 B 支持从 `idor-b-cookie.txt` 预加载
- `scripts/extract-montoya-api.*`：从 `burpsuite.jar` 抽取同版本 API
- `build.sh` / `build.ps1` 构建脚本

### 已知问题
- 响应含动态内容（时间戳 / 随机 token）时，哈希比对失效，只能退化为长度比对
- 重放为手动触发，不做自动扫描
- 仅支持单一身份 B
- 仅覆盖 HTTP，未处理 WebSocket
