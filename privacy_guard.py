#!/usr/bin/env python3
"""
Privacy Guard - MCP Server for Sensitive Information Handling

Usage:
    python privacy_guard.py detect "text"
    python privacy_guard.py redact "text"
    python privacy_guard.py batch-detect "text1,text2,..."
    python privacy_guard.py --mcp
"""

import json
import re
import sys
import os
import pathlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum

try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent
    from mcp.server.stdio import stdio_server

    HAS_MCP = True
except ImportError:
    HAS_MCP = False


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SensitiveInfo:
    info_type: str
    original_value: str
    placeholder: str
    risk_level: str


@dataclass
class CustomRule:
    name: str
    pattern: str
    risk_level: str
    replace_with: str = "[REDACTED]"


class PrivacyGuard:
    def __init__(self):
        self._patterns = self._init_patterns()
        self._counter: Dict[str, int] = {}
        self._last_mapping: Dict[str, str] = {}
        self._custom_rules: List[CustomRule] = []
        self._config_file = str(pathlib.Path(__file__).parent / ".privacy_guard_config.json")
        self._load_config()

    def _init_patterns(self) -> Dict[str, re.Pattern]:
        return {
            "phone": re.compile(r"(?<![\d\-])(?:\+?86[-\s]?)?(1[3-9]\d{9})(?![\d\-])"),
            "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
            "id_card_cn": re.compile(
                r"(?<![\dXx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])"
            ),
            "bank_card": re.compile(
                r"(?<![a-zA-Z0-9])(?:卡号|银行卡|账号|信用卡|储蓄卡)[:：\s]*(\d{12,19})(?![a-zA-Z0-9])"
            ),
            "ssn": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
            "ipv4": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            "ipv6": re.compile(
                r"(?<![:\w])([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![:\w])"
            ),
            "url": re.compile(
                r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
            ),
            "address_cn": re.compile(
                r"(?:[^\w](?:省|市|区|县|路|街|道|号|弄|栋|楼|室|村|镇|乡)[^\n,，]{5,30})|(?:[\u4e00-\u9fa5]{2,6}(?:省|市|区|县))"
            ),
            "wechat": re.compile(
                r"(?<![a-zA-Z0-9])(?:微信号|微信[:：\s]*)[a-zA-Z][a-zA-Z0-9_-]{5,19}(?![a-zA-Z0-9])"
            ),
            "qq": re.compile(
                r"(?<![a-zA-Z0-9])(?:QQ|qq)[:：\s]*(\d{5,11})(?![a-zA-Z0-9])"
            ),
            "license_plate": re.compile(
                r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]"
            ),
            "amount": re.compile(
                r"(?:[￥¥$]\s*[\d,]+(?:\.\d{2})?)|"
                r"(?:[\d,]+(?:\.\d{2})?\s*(?:元|美元|USD|CNY|RMB))"
            ),
        }

    def _get_risk_level(self, info_type: str) -> str:
        risk_map = {
            "id_card_cn": RiskLevel.CRITICAL,
            "ssn": RiskLevel.CRITICAL,
            "bank_card": RiskLevel.HIGH,
            "wechat": RiskLevel.HIGH,
            "phone": RiskLevel.MEDIUM,
            "email": RiskLevel.MEDIUM,
            "qq": RiskLevel.MEDIUM,
            "address_cn": RiskLevel.MEDIUM,
            "license_plate": RiskLevel.MEDIUM,
            "ipv4": RiskLevel.LOW,
            "ipv6": RiskLevel.LOW,
            "amount": RiskLevel.LOW,
            "url": RiskLevel.LOW,
        }
        return risk_map.get(info_type, RiskLevel.MEDIUM).value

    def _generate_placeholder(self, info_type: str) -> str:
        self._counter[info_type] = self._counter.get(info_type, 0) + 1
        return f"[REDACTED_{info_type.upper()}_{self._counter[info_type]}]"

    def _load_config(self):
        if os.path.exists(self._config_file):
            try:
                with open(self._config_file, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    self._custom_rules = [
                        CustomRule(**r) for r in config.get("custom_rules", [])
                    ]
            except Exception:
                pass

    def _save_config(self):
        config = {"custom_rules": [asdict(r) for r in self._custom_rules]}
        with open(self._config_file, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

    def add_custom_rule(
        self,
        name: str,
        pattern: str,
        risk_level: str = "medium",
        replace_with: str = "[REDACTED]",
    ) -> bool:
        try:
            re.compile(pattern)
            rule = CustomRule(
                name=name,
                pattern=pattern,
                risk_level=risk_level,
                replace_with=replace_with,
            )
            self._custom_rules.append(rule)
            self._save_config()
            return True
        except re.error:
            return False

    def remove_custom_rule(self, name: str) -> bool:
        for i, rule in enumerate(self._custom_rules):
            if rule.name == name:
                del self._custom_rules[i]
                self._save_config()
                return True
        return False

    def list_custom_rules(self) -> List[Dict[str, str]]:
        return [asdict(r) for r in self._custom_rules]

    def _detect_in_text(self, text: str) -> List[Dict[str, Any]]:
        detected = []

        for info_type, pattern in self._patterns.items():
            for match in pattern.finditer(text):
                value = (
                    match.group(1)
                    if info_type == "bank_card" and match.group(1)
                    else match.group()
                )
                if info_type == "bank_card" and not value:
                    continue
                placeholder = self._generate_placeholder(info_type)
                detected.append(
                    {
                        "info_type": info_type,
                        "original_value": value,
                        "placeholder": placeholder,
                        "risk_level": self._get_risk_level(info_type),
                    }
                )

        for rule in self._custom_rules:
            pattern = re.compile(rule.pattern)
            for match in pattern.finditer(text):
                value = match.group()
                placeholder = self._generate_placeholder(rule.name)
                detected.append(
                    {
                        "info_type": f"custom:{rule.name}",
                        "original_value": value,
                        "placeholder": placeholder,
                        "risk_level": rule.risk_level,
                        "_replace_with": rule.replace_with,
                    }
                )

        return detected

    def detect(self, text: str) -> List[Dict[str, Any]]:
        self._counter = {}
        return self._detect_in_text(text)

    def batch_detect(self, texts: List[str]) -> List[List[Dict[str, Any]]]:
        self._counter = {}
        return [self._detect_in_text(text) for text in texts]

    def batch_detect_from_file(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            results = []
            for i, line in enumerate(lines):
                detected = self._detect_in_text(line.strip())
                if detected:
                    results.append(
                        {
                            "line": i + 1,
                            "content": line.strip()[:100],
                            "detected": detected,
                        }
                    )

            return {
                "file": file_path,
                "total_lines": len(lines),
                "lines_with_sensitive": len(results),
                "results": results,
            }
        except Exception as e:
            return {"error": str(e)}

    def redact(self, text: str, strategy: str = "placeholder") -> Dict[str, Any]:
        self._counter = {}
        self._last_mapping = {}

        detected = self._detect_in_text(text)

        if not detected:
            return {"text": text, "mapping": {}, "detected_count": 0}

        redacted_text = text
        sorted_items = sorted(
            detected, key=lambda x: text.find(x["original_value"]), reverse=True
        )

        for item in sorted_items:
            placeholder = item["placeholder"]
            original = item["original_value"]

            if strategy == "mask":
                placeholder = self._mask_value(original)
            elif strategy == "remove":
                placeholder = "[REDACTED]"
            elif item.get("_replace_with"):
                suffix = placeholder.split("_")[-1].rstrip("]")
                placeholder = f"{item['_replace_with']}_{suffix}"

            redacted_text = redacted_text.replace(original, placeholder)
            # Store mapping for restore
            self._last_mapping[placeholder] = original

        return {
            "text": redacted_text,
            "mapping": self._last_mapping,
            "detected_count": len(detected),
        }

    def batch_redact(
        self, texts: List[str], strategy: str = "placeholder"
    ) -> List[Dict[str, Any]]:
        return [self.redact(text, strategy) for text in texts]

    def _mask_value(self, value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        elif len(value) <= 8:
            return value[:2] + "*" * (len(value) - 4) + value[-2:]
        else:
            return value[:3] + "*" * (len(value) - 6) + value[-3:]

    def restore(self, text: str, mapping: Dict[str, str]) -> str:
        restored = text
        for placeholder, original in sorted(
            mapping.items(), key=lambda x: len(x[0]), reverse=True
        ):
            restored = restored.replace(placeholder, original)
        return restored


async def run_mcp_server():
    if not HAS_MCP:
        print(
            "Error: MCP dependencies not installed. Run: pip install mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    server = Server("privacy-guard")
    guard = PrivacyGuard()

    @server.list_tools()
    async def list_tools():
        return [
            Tool(
                name="detect",
                description="Detect sensitive information",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to scan"},
                    },
                    "required": ["text"],
                },
            ),
            Tool(
                name="batch_detect",
                description="Detect in multiple texts",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "texts": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of texts to scan",
                        },
                    },
                    "required": ["texts"],
                },
            ),
            Tool(
                name="batch_detect_file",
                description="Detect sensitive info in a file",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to text file",
                        },
                    },
                    "required": ["file_path"],
                },
            ),
            Tool(
                name="redact",
                description="Redact sensitive information",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to redact"},
                        "strategy": {
                            "type": "string",
                            "description": "Strategy: placeholder, mask, remove",
                            "enum": ["placeholder", "mask", "remove"],
                        },
                    },
                    "required": ["text"],
                },
            ),
            Tool(
                name="batch_redact",
                description="Redact multiple texts",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "texts": {"type": "array", "items": {"type": "string"}},
                        "strategy": {
                            "type": "string",
                            "description": "Strategy: placeholder, mask, remove",
                        },
                    },
                    "required": ["texts"],
                },
            ),
            Tool(
                name="add_rule",
                description="Add custom detection rule",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "pattern": {"type": "string", "description": "Regex pattern"},
                        "risk_level": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"],
                        },
                    },
                    "required": ["name", "pattern"],
                },
            ),
            Tool(
                name="list_rules",
                description="List custom rules",
                inputSchema={"type": "object"},
            ),
            Tool(
                name="restore",
                description="Restore redacted text",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "mapping": {"type": "object"},
                    },
                    "required": ["text", "mapping"],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        if name == "detect":
            result = guard.detect(arguments["text"])
            return [
                TextContent(
                    type="text", text=json.dumps(result, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "batch_detect":
            result = guard.batch_detect(arguments["texts"])
            return [
                TextContent(
                    type="text", text=json.dumps(result, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "batch_detect_file":
            result = guard.batch_detect_from_file(arguments["file_path"])
            return [
                TextContent(
                    type="text", text=json.dumps(result, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "redact":
            result = guard.redact(
                arguments["text"], arguments.get("strategy", "placeholder")
            )
            return [
                TextContent(
                    type="text", text=json.dumps(result, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "batch_redact":
            result = guard.batch_redact(
                arguments["texts"], arguments.get("strategy", "placeholder")
            )
            return [
                TextContent(
                    type="text", text=json.dumps(result, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "add_rule":
            success = guard.add_custom_rule(
                arguments["name"],
                arguments["pattern"],
                arguments.get("risk_level", "medium"),
            )
            return [
                TextContent(
                    type="text", text=json.dumps({"success": success}, indent=2)
                )
            ]
        elif name == "list_rules":
            result = guard.list_custom_rules()
            return [
                TextContent(
                    type="text", text=json.dumps(result, ensure_ascii=False, indent=2)
                )
            ]
        elif name == "restore":
            result = guard.restore(arguments["text"], arguments["mapping"])
            return [TextContent(type="text", text=result)]
        raise ValueError(f"Unknown tool: {name}")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


def main():
    guard = PrivacyGuard()
    args = sys.argv[1:]

    if not args:
        print(__doc__)
        print(
            "\nCommands: detect, batch-detect, redact, batch-redact, add-rule, list-rules, restore, --mcp"
        )
        sys.exit(1)

    cmd = args[0]

    if cmd == "detect":
        text = " ".join(args[1:]) if len(args) > 1 else input("Text: ")
        print(json.dumps(guard.detect(text), ensure_ascii=False, indent=2))
    elif cmd == "batch-detect":
        text = (
            " ".join(args[1:]) if len(args) > 1 else input("Texts (comma separated): ")
        )
        texts = [t.strip() for t in text.split(",")]
        print(json.dumps(guard.batch_detect(texts), ensure_ascii=False, indent=2))
    elif cmd == "redact":
        text = " ".join(args[1:]) if len(args) > 1 else input("Text: ")
        print(json.dumps(guard.redact(text), ensure_ascii=False, indent=2))
    elif cmd == "batch-redact":
        text = (
            " ".join(args[1:]) if len(args) > 1 else input("Texts (comma separated): ")
        )
        texts = [t.strip() for t in text.split(",")]
        print(json.dumps(guard.batch_redact(texts), ensure_ascii=False, indent=2))
    elif cmd == "add-rule":
        if len(args) < 3:
            name = input("Rule name: ")
            pattern = input("Regex pattern: ")
        else:
            name, pattern = args[1], args[2]
        success = guard.add_custom_rule(name, pattern)
        print(f"Rule added: {success}")
    elif cmd == "list-rules":
        print(json.dumps(guard.list_custom_rules(), ensure_ascii=False, indent=2))
    elif cmd == "restore":
        if len(args) < 3:
            text = input("Redacted text: ")
            mapping = json.loads(input("Mapping (JSON): "))
        else:
            text, mapping = args[1], json.loads(args[2])
        print(guard.restore(text, mapping))
    elif cmd == "--mcp":
        import asyncio

        asyncio.run(run_mcp_server())
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
