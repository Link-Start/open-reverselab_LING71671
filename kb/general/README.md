# 通用安全知识库

跨平台通用安全/逆向技术知识库。不属于单一平台（Web/Android/Windows）的技术归入此处。

## 结构

```
techniques/
├── crypto/          密码学攻击（算法识别、自定义加密还原、侧信道）
├── protocol/        协议分析（未知协议逆向、状态机推断）
├── firmware/        固件/IoT（binwalk、UBoot、文件系统提取）
├── hardware/        硬件安全（JTAG/SWD、SPI Flash、UART）
├── radio/           无线电安全（BLE、ZigBee、LoRa、NFC）
├── methodology/     逆向方法论（效率优化、命名约定、笔记组织）
└── ai-security/     AI/LLM 安全（prompt injection、模型越狱、RAG 投毒）
```

## 流程

```
信号识别 → kb_router 搜索 → 阅读技术文件 → 选择工具 → 执行 → 证据落盘
```

## 工具映射

参见各技术文件末尾的"## MCP 工具映射"表。

## 原则

- 伪代码可直接运行
- 跨平台优先，单平台技术归入对应板块
- 证据落盘到 `exports/general/`
