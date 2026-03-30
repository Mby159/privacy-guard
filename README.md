# Privacy Guard

敏感信息检测、脱敏、恢复工具。

## 功能

- 检测敏感信息
- 脱敏处理 (placeholder/mask/remove)
- 批量处理
- 自定义规则

## 支持的类型

| 类型 | 风险等级 |
|------|----------|
| 手机号 | medium |
| 邮箱 | medium |
| 身份证 | critical |
| 银行卡 | high |
| 微信号 | high |
| QQ号 | medium |
| IP地址 | low |

## 安装

```bash
pip install mcp
```

## 使用

```bash
# 检测
python privacy_guard.py detect "手机号13812345678"

# 脱敏
python privacy_guard.py redact "手机号13812345678"

# 批量检测
python privacy_guard.py batch-detect "text1,text2"

# 自定义规则
python privacy_guard.py add-rule "订单号" "\d{10,}"
```

## MCP Server

```bash
python privacy_guard.py --mcp
```
