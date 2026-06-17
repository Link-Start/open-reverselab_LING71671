# GhidraMCP

Ghidra MCP 桥接服务器，允许 AI 通过 MCP 协议与 Ghidra 交互。

## 安装

```bash
git clone <ghidra-mcp-repo-url> tools/skills/mcp/GhidraMCP
cd tools/skills/mcp/GhidraMCP
uv sync
```

## 使用

1. 启动 Ghidra headless server 在 `http://127.0.0.1:18080/`
2. MCP 配置已在 `.mcp.json` 中预设
