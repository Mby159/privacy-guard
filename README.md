# File Brain MCP

本地文件系统智能管理 - 搜索、索引、问答功能。

## 功能

- 关键词搜索
- 向量搜索 (需要 numpy)
- 中文分词 (需要 jieba)
- 增量索引
- AI 问答

## 安装

```bash
pip install numpy jieba mcp
```

## 使用

```bash
# 索引
python file_brain_mcp.py index-dir ./docs/

# 搜索
python file_brain_mcp.py search "关键词"
python file_brain_mcp.py vector-search "语义查询"

# 问答
python file_brain_mcp.py ask "问题"

# 增量索引
python file_brain_mcp.py reindex ./docs/
```

## MCP Server

```bash
python file_brain_mcp.py --mcp
```
