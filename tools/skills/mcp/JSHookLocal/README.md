# JSHookLocal

浏览器 JavaScript Hook 和自动化 MCP 服务器。

## 安装

```bash
git clone <jshook-repo-url> tools/skills/mcp/JSHookLocal
cd tools/skills/mcp/JSHookLocal
npm install
npm run build
```

## 配置

环境变量见 `.env.example`。默认使用无 LLM 模式 (`DEFAULT_LLM_PROVIDER=none`)。

## 使用

MCP 配置已在 `.mcp.json` 中预设。启动后可通过 Puppeteer 控制浏览器执行 JS hook。
