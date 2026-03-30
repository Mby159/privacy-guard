#!/usr/bin/env python3
"""
File Brain MCP Server - 本地文件系统智能管理
提供搜索、索引、问答功能

Usage:
    # As MCP server
    python file_brain_mcp.py --mcp

    # As CLI
    python file_brain_mcp.py index ./docs/
    python file_brain_mcp.py search "关键词"
    python file_brain_mcp.py ask "文件在哪里？"
    python file_brain_mcp.py reindex  # 增量索引
    python file_brain_mcp.py vector-search "语义搜索"
"""

import json
import os
import sys
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import hashlib

try:
    import jieba

    jieba.setLogLevel(jieba.logging.INFO)
    HAS_JIEBA = True
except ImportError:
    HAS_JIEBA = False

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent
    from mcp.server.stdio import stdio_server

    HAS_MCP = True
except ImportError:
    HAS_MCP = False


@dataclass
class FileContent:
    source: str
    content: str
    file_type: str
    title: str
    metadata: Dict[str, Any]


class SimpleSearchEngine:
    def __init__(self, index_dir: str = ".file_brain_index"):
        self.index_dir = Path(index_dir)
        self.index_dir.mkdir(exist_ok=True)
        self.index_file = self.index_dir / "index.json"
        self.index: Dict[str, Dict] = {}
        self._load_index()

        self.use_chinese = HAS_JIEBA
        self.use_vector = HAS_NUMPY
        self._vectors: Dict[str, List[float]] = {}
        self._vector_file = self.index_dir / "vectors.json"
        self._load_vectors()

    def _load_index(self):
        if self.index_file.exists():
            with open(self.index_file, "r", encoding="utf-8") as f:
                self.index = json.load(f)

    def _save_index(self):
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(self.index, f, ensure_ascii=False, indent=2)

    def _load_vectors(self):
        if self._vector_file.exists():
            with open(self._vector_file, "r", encoding="utf-8") as f:
                self._vectors = json.load(f)

    def _save_vectors(self):
        with open(self._vector_file, "w", encoding="utf-8") as f:
            json.dump(self._vectors, f, ensure_ascii=False)

    def _tokenize(self, text: str) -> List[str]:
        if self.use_chinese:
            return list(jieba.cut(text))
        return text.lower().split()

    def _compute_vector(self, text: str) -> Optional[List[float]]:
        if not self.use_vector:
            return None
        tokens = self._tokenize(text)
        if not tokens:
            return None
        vec = np.zeros(min(len(tokens), 100))
        seen = set()
        for i, t in enumerate(tokens[:100]):
            if t not in seen:
                vec[i] = 1
                seen.add(t)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()

    def _cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        if not self.use_vector or not v1 or not v2:
            return 0.0
        dot = sum(a * b for a, b in zip(v1, v2))
        return max(0, dot)

    def _read_file(self, file_path: Path) -> Optional[str]:
        ext = file_path.suffix.lower()
        try:
            if ext in [
                ".txt",
                ".md",
                ".py",
                ".js",
                ".ts",
                ".json",
                ".yaml",
                ".yml",
                ".html",
                ".css",
                ".xml",
                ".csv",
                ".log",
            ]:
                return file_path.read_text(encoding="utf-8", errors="ignore")
            elif ext == ".pdf":
                return f"[PDF文件: {file_path.name}]"
            elif ext in [".docx", ".xlsx", ".pptx"]:
                return f"[Office文档: {file_path.name}]"
            else:
                return f"[{ext}文件: {file_path.name}]"
        except Exception:
            return None

    def _index_single_file(self, file_path: Path) -> bool:
        content = self._read_file(file_path)
        if not content:
            return False

        source = str(file_path.absolute())
        mtime = file_path.stat().st_mtime

        self.index[source] = {
            "content": content,
            "file_type": file_path.suffix,
            "title": file_path.name,
            "size": file_path.stat().st_size,
            "modified": mtime,
        }

        vec = self._compute_vector(content)
        if vec:
            self._vectors[source] = vec

        self._save_index()
        self._save_vectors()
        return True

    def index_directory(
        self,
        directory: Path,
        recursive: bool = True,
        extensions: List[str] = None,
        incremental: bool = True,
    ) -> Dict[str, int]:
        stats = {"success": 0, "failed": 0, "skipped": 0, "updated": 0}

        if extensions is None:
            extensions = [
                ".txt",
                ".md",
                ".py",
                ".js",
                ".ts",
                ".json",
                ".yaml",
                ".yml",
                ".html",
                ".css",
                ".xml",
            ]

        pattern = "**/*" if recursive else "*"

        for file_path in directory.glob(pattern):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in extensions:
                stats["skipped"] += 1
                continue

            source = str(file_path.absolute())
            mtime = file_path.stat().st_mtime

            if incremental and source in self.index:
                if self.index[source].get("modified") == mtime:
                    stats["skipped"] += 1
                    continue
                else:
                    stats["updated"] += 1
            elif source in self.index:
                stats["updated"] += 1

            if self._index_single_file(file_path):
                stats["success"] += 1
            else:
                stats["failed"] += 1

        return stats

    def reindex_modified(self, directory: Path) -> Dict[str, int]:
        return self.index_directory(directory, incremental=True)

    def search(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        query_lower = query.lower()
        query_tokens = self._tokenize(query)
        results = []

        for source, data in self.index.items():
            content = data["content"]
            content_lower = content.lower()

            if query_lower in content_lower:
                lines = content.split("\n")
                matches = [
                    i for i, line in enumerate(lines) if query_lower in line.lower()
                ]
                context = ""
                if matches:
                    idx = matches[0]
                    start = max(0, idx - 2)
                    end = min(len(lines), idx + 3)
                    context = "\n".join(lines[start:end])

                score = content_lower.count(query_lower)

                if self.use_chinese and query_tokens:
                    content_tokens = set(self._tokenize(content))
                    token_matches = len(set(query_tokens) & content_tokens)
                    score += token_matches * 0.5

                results.append(
                    {
                        "source": source,
                        "title": data["title"],
                        "file_type": data["file_type"],
                        "score": round(score, 2),
                        "context": context[:500],
                        "preview": data["content"][:200],
                    }
                )

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def vector_search(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        if not self.use_vector:
            return [{"error": "向量搜索需要 numpy: pip install numpy"}]

        query_vec = self._compute_vector(query)
        if not query_vec:
            return [{"error": "无法处理查询文本"}]

        results = []
        for source, data in self.index.items():
            if source not in self._vectors:
                continue
            sim = self._cosine_similarity(query_vec, self._vectors[source])
            if sim > 0.1:
                results.append(
                    {
                        "source": source,
                        "title": data["title"],
                        "file_type": data["file_type"],
                        "score": round(sim, 4),
                        "preview": data["content"][:200],
                    }
                )

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def list_sources(self, with_preview: bool = False) -> List[Dict[str, Any]]:
        result = []
        for source, data in self.index.items():
            item = {
                "source": source,
                "title": data["title"],
                "file_type": data["file_type"],
                "size": data["size"],
            }
            if with_preview:
                content = data["content"]
                item["preview"] = (
                    (content[:300] + "...") if len(content) > 300 else content
                )
            result.append(item)
        return result

    def get_stats(self) -> Dict[str, Any]:
        total_files = len(self.index)
        total_content = sum(len(d["content"]) for d in self.index.values())
        file_types = {}
        for d in self.index.values():
            ft = d["file_type"]
            file_types[ft] = file_types.get(ft, 0) + 1

        return {
            "total_files": total_files,
            "total_content_chars": total_content,
            "file_types": file_types,
            "features": {
                "chinese_tokenize": self.use_chinese,
                "vector_search": self.use_vector,
            },
        }

    def delete(self, source: str) -> bool:
        if source in self.index:
            del self.index[source]
            self._vectors.pop(source, None)
            self._save_index()
            self._save_vectors()
            return True
        return False

    def clear(self) -> bool:
        self.index = {}
        self._vectors = {}
        self._save_index()
        self._save_vectors()
        return True


class QaEngine:
    def __init__(self, search_engine: SimpleSearchEngine):
        self.search_engine = search_engine

    def ask(self, question: str, top_k: int = 5) -> Dict[str, Any]:
        results = self.search_engine.search(question, top_k=top_k)

        if not results:
            results = self.search_engine.vector_search(question, top_k=top_k)
            if not results or "error" in results[0]:
                return {"answer": "没有找到相关内容。", "sources": []}

        context = "\n\n".join(
            [
                f"[{r['title']}]\n{r.get('context', r.get('preview', ''))}"
                for r in results[:3]
                if r.get("context") or r.get("preview")
            ]
        )

        answer = f"根据索引内容，找到 {len(results)} 个相关结果。\n\n"
        answer += f"最相关的内容来自：\n"
        for r in results[:3]:
            answer += f"- {r['title']} (匹配度: {r['score']})\n"
            ctx = r.get("context") or r.get("preview", "")
            if ctx:
                answer += f"  上下文: {ctx[:200]}...\n"

        return {
            "answer": answer,
            "sources": [
                {"title": r["title"], "source": r["source"]} for r in results[:3]
            ],
            "total_found": len(results),
        }


async def run_mcp_server():
    if not HAS_MCP:
        print(
            "Error: MCP dependencies not installed. Run: pip install mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    server = Server("file-brain")
    engine = SimpleSearchEngine()
    qa = QaEngine(engine)

    @server.list_tools()
    async def list_tools():
        return [
            Tool(
                name="search",
                description="Search indexed files for content",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "top_k": {
                            "type": "integer",
                            "description": "Max results",
                            "default": 10,
                        },
                    },
                    "required": ["query"],
                },
            ),
            Tool(
                name="vector_search",
                description="Semantic search using embeddings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Semantic query"},
                        "top_k": {
                            "type": "integer",
                            "description": "Max results",
                            "default": 10,
                        },
                    },
                    "required": ["query"],
                },
            ),
            Tool(
                name="index_file",
                description="Index a single file",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to index"},
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="index_directory",
                description="Index all files in a directory",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Directory path"},
                        "recursive": {
                            "type": "boolean",
                            "description": "Recursive search",
                            "default": True,
                        },
                        "incremental": {
                            "type": "boolean",
                            "description": "Only update modified files",
                            "default": True,
                        },
                        "extensions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "File extensions to index (e.g., [\".py\", \".md\"])",
                        },
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="reindex",
                description="Reindex only modified files",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path to check",
                        },
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="ask",
                description="Ask questions about indexed content",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "question": {
                            "type": "string",
                            "description": "Question to ask",
                        },
                        "top_k": {
                            "type": "integer",
                            "description": "Results to consider",
                            "default": 5,
                        },
                    },
                    "required": ["question"],
                },
            ),
            Tool(
                name="list_indexed",
                description="List all indexed files",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "with_preview": {
                            "type": "boolean",
                            "description": "Include content preview",
                            "default": False,
                        },
                    },
                },
            ),
            Tool(
                name="get_stats",
                description="Get indexing statistics",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        if name == "search":
            results = engine.search(arguments["query"], arguments.get("top_k", 10))
            return [
                TextContent(
                    type="text", text=json.dumps(results, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "vector_search":
            results = engine.vector_search(
                arguments["query"], arguments.get("top_k", 10)
            )
            return [
                TextContent(
                    type="text", text=json.dumps(results, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "index_file":
            success = engine._index_single_file(Path(arguments["path"]))
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {"success": success, "stats": engine.get_stats()}, indent=2
                    ),
                )
            ]
        elif name == "index_directory":
            stats = engine.index_directory(
                Path(arguments["path"]),
                recursive=arguments.get("recursive", True),
                extensions=arguments.get("extensions"),
                incremental=arguments.get("incremental", True),
            )
            return [TextContent(type="text", text=json.dumps(stats, indent=2))]
        elif name == "reindex":
            stats = engine.reindex_modified(Path(arguments["path"]))
            return [TextContent(type="text", text=json.dumps(stats, indent=2))]
        elif name == "ask":
            result = qa.ask(arguments["question"], arguments.get("top_k", 5))
            return [
                TextContent(
                    type="text", text=json.dumps(result, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "list_indexed":
            sources = engine.list_sources(arguments.get("with_preview", False))
            return [
                TextContent(
                    type="text", text=json.dumps(sources, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "get_stats":
            return [
                TextContent(type="text", text=json.dumps(engine.get_stats(), indent=2))
            ]
        raise ValueError(f"Unknown tool: {name}")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


def main():
    engine = SimpleSearchEngine()
    qa = QaEngine(engine)
    args = sys.argv[1:]

    if not args:
        print(__doc__)
        print(
            "\nAvailable commands: search, index, index-dir, reindex, vector-search, ask, list, stats, clear"
        )
        sys.exit(1)

    cmd = args[0]

    if cmd == "search":
        query = " ".join(args[1:]) if len(args) > 1 else input("Query: ")
        print(json.dumps(engine.search(query), ensure_ascii=False, indent=2))
    elif cmd == "vector-search":
        query = " ".join(args[1:]) if len(args) > 1 else input("Semantic query: ")
        print(json.dumps(engine.vector_search(query), ensure_ascii=False, indent=2))
    elif cmd == "index":
        if len(args) < 2:
            print("Usage: file_brain_mcp.py index <file_path>")
            sys.exit(1)
        print(f"Indexed: {engine._index_single_file(Path(args[1]))}")
    elif cmd == "index-dir":
        if len(args) < 2:
            print("Usage: file_brain_mcp.py index-dir <directory_path>")
            sys.exit(1)
        print(json.dumps(engine.index_directory(Path(args[1])), indent=2))
    elif cmd == "reindex":
        if len(args) < 2:
            print("Usage: file_brain_mcp.py reindex <directory_path>")
            sys.exit(1)
        print(json.dumps(engine.reindex_modified(Path(args[1])), indent=2))
    elif cmd == "ask":
        question = " ".join(args[1:]) if len(args) > 1 else input("Question: ")
        print(json.dumps(qa.ask(question), ensure_ascii=False, indent=2))
    elif cmd == "list":
        preview = "--preview" in args
        print(
            json.dumps(
                engine.list_sources(with_preview=preview), ensure_ascii=False, indent=2
            )
        )
    elif cmd == "stats":
        print(json.dumps(engine.get_stats(), indent=2))
    elif cmd == "clear":
        engine.clear()
        print("Index cleared")
    elif cmd == "--mcp":
        asyncio.run(run_mcp_server())
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
