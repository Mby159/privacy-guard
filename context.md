# Leon 的上下文记忆

## 个人信息
- 称呼：Leon
- 这是个人项目，非工作相关

## 项目概览
两个基于 AI 的 Python 项目：

### file-brain (D:\trae1\5file brain)
文件内容索引与搜索系统
- 内容索引 + 向量搜索
- 知识图谱
- 支持 PDF/Notion/Obsidian
- AI 问答引擎

### splitmind (D:\trae1\3\splitmind)
隐私保护的多智能体任务编排系统
- 任务拆分 → 分发 → 聚合
- Provider 插件架构
- PrivacyHandler 敏感信息处理

## 已集成的 Skill
两个项目已封装为 opencode skill：
- `file-brain`：搜索/索引本地文件
- `privacy-guard`：检测/脱敏敏感信息

## 设计背景
- Leon 和 AI 一起开发了这两个项目
- skill 是为了在 opencode 中调用项目能力
- 没有特定代码风格偏好，保持灵活

## 对话记录

### 2026-03-30
- 测试了两个 skill，均正常工作
- 讨论了 AI 记忆问题，决定创建 context.md 持久化上下文

### 2026-03-30 (后续)
- 改进了 file-brain: list 命令添加 --preview 选项返回内容预览
- 改进了 privacy-guard: 
  - 银行卡检测需要关键词前缀，避免误匹配身份证
  - 添加中文地址检测
  - 正确区分身份证/银行卡/手机号/IP

### 2026-03-30 (第二轮改进)
**file-brain 新功能:**
- 中文分词 (jieba): pip install jieba
- 增量索引: 自动跳过未修改文件
- 向量搜索: 基于 numpy，支持语义搜索
- 新命令: vector-search, reindex

**privacy-guard 新功能:**
- 批量 API: batch_detect, batch_redact
- 新增类型: 微信号、QQ号、车牌号、IPv6
- 自定义规则: add_rule, list_rules


## Skill 配置说明
- 单一事实源: C:/Users/22324/.config/opencode/skills/*/SKILL.md
- Python 脚本: D:/opencode1/*.py (实现)
- Skill 配置与实现需同步更新

### 2026-03-30 (Bug Fix)
- 修复自定义规则多命中时占位符冲突问题 (privacy_guard.py)
  - 每个匹配现在有唯一占位符如 [ORDER]_1, [ORDER]_2
  - 恢复功能现在能正确还原所有值