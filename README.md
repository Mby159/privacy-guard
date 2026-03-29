# Privacy Guard / 隐私保护

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**English:** A tool for detecting, redacting, and restoring sensitive information in text. Supports phone numbers, emails, ID cards, bank cards, SSN, IP addresses, URLs, and amounts.

**中文:** 用于检测、脱敏和恢复文本中敏感信息的工具。支持手机号、邮箱、身份证、银行卡、SSN、IP 地址、URL 和金额。

---

## Features / 功能特点

- **Detect** - 自动检测文本中的敏感信息
- **Redact** - 用占位符替换敏感信息
- **Restore** - 使用映射恢复原始值
- **Multiple Types** - 支持多种敏感数据类型
- **Risk Level** - 为每种类型评估风险等级
- **CLI & MCP** - 同时提供命令行和 MCP Server 接口

## Supported Types / 支持的类型

| Type | Description | Risk Level |
|------|-------------|------------|
| phone | 手机号 / Phone number | Medium |
| email | 邮箱 / Email | Medium |
| id_card_cn | 身份证 / Chinese ID card | Critical |
| bank_card | 银行卡 / Bank card | High |
| ssn | 社保号 / SSN | Critical |
| amount | 金额 / Financial amounts | Low |
| ipv4 | IP 地址 / IP address | Low |
| url | URL | Low |

---

## Installation / 安装

```bash
# Clone / 克隆
git clone https://github.com/Mby159/privacy-guard.git
cd privacy-guard

# Install / 安装
pip install -e .

# Or / 或者
pip install .
```

### Install with MCP support / 安装 MCP 支持

```bash
pip install -e ".[mcp]"
```

---

## Usage / 使用方法

### CLI

```bash
# Detect sensitive information / 检测敏感信息
python privacy_guard.py detect "手机号是13812345678，邮箱是test@example.com"

# Redact / 脱敏
python privacy_guard.py redact "手机号是13812345678"

# Redact with mask strategy / 使用遮罩策略脱敏
python privacy_guard.py redact --strategy mask "手机号是13812345678"

# Restore / 恢复
python privacy_guard.py restore "[REDACTED_PHONE_1]" '{"[REDACTED_PHONE_1]": "13812345678"}'
```

### Python API

```python
from privacy_guard import PrivacyGuard

guard = PrivacyGuard()

# Detect / 检测
detected = guard.detect("手机号是13812345678")
print(detected)
# [{'info_type': 'phone', 'original_value': '13812345678', ...}]

# Redact / 脱敏
result = guard.redact("手机号是13812345678")
print(result['text'])  # 手机号是[REDACTED_PHONE_1]
print(result['mapping'])  # {'[REDACTED_PHONE_1]': '13812345678'}

# Restore / 恢复
restored = guard.restore(result['text'], result['mapping'])
print(restored)  # 手机号是13812345678
```

### MCP Server

```bash
# Start MCP server / 启动 MCP Server
python privacy_guard.py --mcp

# Configure in OpenCode or other MCP clients / 在 OpenCode 或其他 MCP 客户端中配置
```

#### MCP Configuration / MCP 配置

```json
{
  "mcpServers": {
    "privacy-guard": {
      "command": "python",
      "args": ["/path/to/privacy_guard.py", "--mcp"]
    }
  }
}
```

---

## Examples / 示例

### Basic / 基础用法

```python
from privacy_guard import PrivacyGuard

guard = PrivacyGuard()
text = "用户手机号是13812345678，邮箱是test@example.com，银行卡是1234567890123456"

# Detect all sensitive info / 检测所有敏感信息
detected = guard.detect(text)
for item in detected:
    print(f"{item['info_type']}: {item['original_value']} ({item['risk_level']})")
# phone: 13812345678 (medium)
# email: test@example.com (medium)
# bank_card: 1234567890123456 (high)

# Redact / 脱敏
result = guard.redact(text)
print(result['text'])
# 用户手机号是[REDACTED_PHONE_1]，邮箱是[REDACTED_EMAIL_1]，银行卡是[REDACTED_BANK_CARD_1]

# Restore / 恢复
restored = guard.restore(result['text'], result['mapping'])
print(restored)
# 用户手机号是13812345678，邮箱是test@example.com，银行卡是1234567890123456
```

### With Different Strategies / 不同策略

```python
# Placeholder (default) / 占位符（默认）
guard.redact("手机13812345678", strategy="placeholder")
# 手机[REDACTED_PHONE_1]

# Mask / 遮罩
guard.redact("手机13812345678", strategy="mask")
# 手机138****5678

# Remove / 删除
guard.redact("手机13812345678", strategy="remove")
# 手机[REDACTED]
```

---

## License / 许可证

MIT License - see [LICENSE](LICENSE) for details.

---

## Contributing / 贡献

Issues and Pull Requests are welcome! / 欢迎提交 Issue 和 Pull Request！
