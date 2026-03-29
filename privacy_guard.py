#!/usr/bin/env python3
"""
Privacy Guard - MCP Server & CLI Tool for Sensitive Information Handling

Usage:
    # As CLI
    python privacy_guard.py detect "text with 13812345678"
    python privacy_guard.py redact "text with sensitive data"
    python privacy_guard.py restore "redacted text" '{"[REDACTED_PHONE_1]": "13812345678"}'

    # As MCP server
    python privacy_guard.py --mcp
"""

import json
import re
import sys
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
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


class PrivacyGuard:
    def __init__(self):
        self._patterns = self._init_patterns()
        self._counter: Dict[str, int] = {}
        self._last_mapping: Dict[str, str] = {}

    def _init_patterns(self) -> Dict[str, re.Pattern]:
        return {
            "phone": re.compile(r"(?<![\d\-])(?:\+?86[-\s]?)?(1[3-9]\d{9})(?![\d\-])"),
            "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
            "id_card_cn": re.compile(
                r"(?<![\dXx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])"
            ),
            "bank_card": re.compile(
                r"(?<![\d])\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?![\d])"
            ),
            "ssn": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
            "amount": re.compile(
                r"(?:[￥¥$]\s*[\d,]+(?:\.\d{2})?)|(?:[\d,]+(?:\.\d{2})?\s*(?:元|美元|USD|CNY|RMB))"
            ),
            "ipv4": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            "url": re.compile(
                r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
            ),
        }

    def _get_risk_level(self, info_type: str) -> str:
        risk_map = {
            "id_card_cn": RiskLevel.CRITICAL,
            "ssn": RiskLevel.CRITICAL,
            "bank_card": RiskLevel.HIGH,
            "phone": RiskLevel.MEDIUM,
            "email": RiskLevel.MEDIUM,
            "amount": RiskLevel.LOW,
            "ipv4": RiskLevel.LOW,
            "url": RiskLevel.LOW,
        }
        return risk_map.get(info_type, RiskLevel.MEDIUM).value

    def _generate_placeholder(self, info_type: str) -> str:
        self._counter[info_type] = self._counter.get(info_type, 0) + 1
        return f"[REDACTED_{info_type.upper()}_{self._counter[info_type]}]"

    def detect(self, text: str) -> List[Dict[str, Any]]:
        detected = []
        for info_type, pattern in self._patterns.items():
            for match in pattern.finditer(text):
                value = match.group()
                placeholder = self._generate_placeholder(info_type)
                detected.append(
                    asdict(
                        SensitiveInfo(
                            info_type=info_type,
                            original_value=value,
                            placeholder=placeholder,
                            risk_level=self._get_risk_level(info_type),
                        )
                    )
                )
        return detected

    def redact(self, text: str, strategy: str = "placeholder") -> Dict[str, Any]:
        self._counter = {}
        self._last_mapping = {}
        detected = self.detect(text)

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
            redacted_text = redacted_text.replace(original, placeholder)
            self._last_mapping[placeholder] = original

        return {
            "text": redacted_text,
            "mapping": self._last_mapping,
            "detected_count": len(detected),
        }

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
                description="Detect sensitive information in text (phone, email, ID, bank card, etc.)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to scan"}
                    },
                    "required": ["text"],
                },
            ),
            Tool(
                name="redact",
                description="Redact sensitive information from text",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to redact"},
                        "strategy": {
                            "type": "string",
                            "description": "Strategy: placeholder (default), mask, or remove",
                            "enum": ["placeholder", "mask", "remove"],
                        },
                    },
                    "required": ["text"],
                },
            ),
            Tool(
                name="restore",
                description="Restore redacted text to original using mapping",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Redacted text"},
                        "mapping": {
                            "type": "object",
                            "description": "Mapping from placeholders to original values",
                        },
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
        elif name == "redact":
            strategy = arguments.get("strategy", "placeholder")
            result = guard.redact(arguments["text"], strategy)
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
        print("\nAvailable commands: detect, redact, restore")
        sys.exit(1)

    cmd = args[0]

    if cmd == "detect":
        text = " ".join(args[1:]) if len(args) > 1 else input("Text: ")
        print(json.dumps(guard.detect(text), ensure_ascii=False, indent=2))

    elif cmd == "redact":
        text = " ".join(args[1:]) if len(args) > 1 else input("Text: ")
        strategy = "placeholder"
        for i, a in enumerate(args):
            if a == "--strategy" and i + 1 < len(args):
                strategy = args[i + 1]
        print(json.dumps(guard.redact(text, strategy), ensure_ascii=False, indent=2))

    elif cmd == "restore":
        if len(args) < 3:
            text = input("Redacted text: ")
            mapping = json.loads(input("Mapping (JSON): "))
        else:
            text = args[1]
            mapping = json.loads(args[2])
        print(guard.restore(text, mapping))

    elif cmd == "--mcp":
        import asyncio

        asyncio.run(run_mcp_server())

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
