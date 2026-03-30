#!/usr/bin/env python3
"""
Privacy Guard - MCP Server & CLI Tool for Sensitive Information Handling

Usage:
    # As CLI
    python privacy_guard.py detect "text with 13812345678"
    python privacy_guard.py detect "text" --format table
    python privacy_guard.py redact "text with sensitive data"
    python privacy_guard.py redact-file data.txt --output redacted.txt
    python privacy_guard.py scan-dir ./project/ --format table
    python privacy_guard.py detect --config rules.json

    # As MCP server
    python privacy_guard.py --mcp
"""

import json
import re
import sys
import os
import fnmatch
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


def safe_print(text: str):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('utf-8', errors='replace').decode('utf-8'))


def format_detect_table(results: List[Dict[str, Any]]) -> str:
    if not results:
        return "No sensitive information detected."
    header = f"{'Type':<20} {'Value':<30} {'Risk Level':<10}"
    separator = "-" * 62
    lines = [header, separator]
    for r in results:
        value = r["original_value"]
        if len(value) > 27:
            value = value[:24] + "..."
        lines.append(f"{r['info_type']:<20} {value:<30} {r['risk_level']:<10}")
    return "\n".join(lines)


class PrivacyGuard:
    def __init__(self):
        self._patterns = self._init_patterns()
        self._custom_rules: Dict[str, Dict[str, Any]] = {}
        self._counter: Dict[str, int] = {}
        self._last_mapping: Dict[str, str] = {}
        self._ignore_patterns: List[str] = []

    def _init_patterns(self) -> Dict[str, re.Pattern]:
        return {
            "phone": re.compile(r"(?<![\d\-])(?:\+?86[-\s]?)?(1[3-9]\d{9})(?![\d\-])"),
            "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
            "id_card_cn": re.compile(r"(?<![\dXx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])"),
            "bank_card": re.compile(r"(?<![\d])\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?![\d])"),
            "ssn": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
            "amount": re.compile(r"(?:[￥¥$]\s*[\d,]+(?:\.\d{2})?)|(?:[\d,]+(?:\.\d{2})?\s*(?:元|美元|USD|CNY|RMB))"),
            "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
            "url": re.compile(r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"),
            "china_passport": re.compile(r"(?<![\dA-Z])[A-Z]\d{8,9}(?![\dA-Z])"),
            "china_credit_code": re.compile(r"(?<![\d])91[12]\d{16}(?![\d])"),
            "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        }

    def _luhn_check(self, card_number: str) -> bool:
        digits = [int(d) for d in card_number if d.isdigit()]
        if not digits:
            return False
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    def _validate_credit_code(self, code: str) -> bool:
        if len(code) != 18:
            return False
        weight = [3, 7, 9, 10, 5, 8, 4, 2, 0, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_codes = "0123456789ABCDEFGHJKLMNPQRTUWXY"
        code_upper = code.upper()
        try:
            checksum = sum(weight[i] * check_codes.index(code_upper[i]) for i in range(17))
            return code_upper[17] == check_codes[checksum % 31]
        except (ValueError, IndexError):
            return False

    def _get_risk_level(self, info_type: str) -> str:
        risk_map = {
            "id_card_cn": RiskLevel.CRITICAL,
            "ssn": RiskLevel.CRITICAL,
            "china_passport": RiskLevel.HIGH,
            "jwt_token": RiskLevel.HIGH,
            "bank_card": RiskLevel.HIGH,
            "china_credit_code": RiskLevel.CRITICAL,
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

    def add_rule(self, name: str, pattern: str, risk_level: str = "medium"):
        try:
            self._custom_rules[name] = {"pattern": re.compile(pattern), "risk_level": risk_level}
            self._patterns[name] = self._custom_rules[name]["pattern"]
            return True
        except re.error:
            return False

    def list_rules(self) -> List[Dict[str, Any]]:
        return [{"name": n, "risk_level": self._custom_rules[n]["risk_level"], "is_custom": True} 
                for n in self._patterns if n in self._custom_rules]

    def export_config_example(self) -> str:
        return json.dumps({"rules": [{"name": "order_id", "pattern": r"订单号[:：]\s*([A-Z0-9]{10,20})", "risk_level": "low"}]}, ensure_ascii=False, indent=2)

    def load_rules_from_config(self, config_path: str) -> Dict[str, Any]:
        if not os.path.exists(config_path):
            return {"error": f"Config file not found: {config_path}"}
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {str(e)}"}
        except Exception as e:
            return {"error": f"Failed to read config: {str(e)}"}
        
        added = []
        errors = []
        for rule in config.get("rules", []):
            name = rule.get("name")
            pattern = rule.get("pattern")
            risk_level = rule.get("risk_level", "medium")
            if name and pattern:
                if self.add_rule(name, pattern, risk_level):
                    added.append(name)
                else:
                    errors.append(f"Invalid pattern for '{name}'")
        
        return {"added": added, "errors": errors, "total_added": len(added)}

    def detect(self, text: str, skip_validation: bool = False) -> List[Dict[str, Any]]:
        detected = []
        for info_type, pattern in self._patterns.items():
            for match in pattern.finditer(text):
                value = match.group()
                if info_type == "bank_card" and not skip_validation:
                    if not self._luhn_check(value.replace("-", "").replace(" ", "")):
                        continue
                elif info_type == "china_credit_code" and not skip_validation:
                    if not self._validate_credit_code(value.replace("-", "").replace(" ", "")):
                        continue
                detected.append(asdict(SensitiveInfo(info_type=info_type, original_value=value, placeholder=self._generate_placeholder(info_type), risk_level=self._get_risk_level(info_type))))
        return detected

    def batch_detect(self, texts: List[str]) -> List[List[Dict[str, Any]]]:
        return [self.detect(t) for t in texts]

    def batch_redact(self, texts: List[str], strategy: str = "placeholder") -> List[Dict[str, Any]]:
        return [self.redact(t, strategy) for t in texts]

    def redact_file(self, file_path: str, output_path: Optional[str] = None, strategy: str = "placeholder") -> Dict[str, Any]:
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {str(e)}"}
        result = self.redact(content, strategy)
        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(result["text"])
                result["output_file"] = output_path
            except Exception as e:
                return {"error": f"Failed to write file: {str(e)}"}
        return result

    def scan_directory(self, directory: str, extensions: Optional[List[str]] = None, recursive: bool = True, exclude_git: bool = True) -> Dict[str, Any]:
        if not os.path.exists(directory):
            return {"error": f"Directory not found: {directory}"}
        if not os.path.isdir(directory):
            return {"error": f"Not a directory: {directory}"}
        
        ignore_file = os.path.join(directory, ".privacy-guard-ignore")
        self._ignore_patterns = []
        if os.path.exists(ignore_file):
            with open(ignore_file, "r", encoding="utf-8") as f:
                self._ignore_patterns = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        default_ignores = [".git"] if exclude_git else []
        self._ignore_patterns = default_ignores + self._ignore_patterns
        
        results = {"files": [], "total_files": 0, "total_findings": 0, "high_risk_files": []}
        
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, pat) for pat in self._ignore_patterns)]
            
            for filename in files:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, directory)
                
                if any(fnmatch.fnmatch(filename, pat) for pat in self._ignore_patterns):
                    continue
                if any(fnmatch.fnmatch(rel_path, pat) for pat in self._ignore_patterns):
                    continue
                
                if extensions and not any(filename.endswith(ext) for ext in extensions):
                    continue
                
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                
                findings = self.detect(content)
                if findings:
                    results["files"].append({"file": rel_path, "findings": findings, "count": len(findings)})
                    results["total_findings"] += len(findings)
                    if any(f["risk_level"] in ["high", "critical"] for f in findings):
                        results["high_risk_files"].append(rel_path)
        
        results["total_files"] = len(results["files"])
        return results

    def redact(self, text: str, strategy: str = "placeholder") -> Dict[str, Any]:
        self._counter = {}
        self._last_mapping = {}
        detected = self.detect(text)
        if not detected:
            return {"text": text, "mapping": {}, "detected_count": 0}
        redacted_text = text
        positions = [(text.find(i["original_value"]), len(i["original_value"]), i) for i in detected if text.find(i["original_value"]) >= 0]
        positions.sort(key=lambda x: x[0], reverse=True)
        for pos, length, item in positions:
            placeholder = item["placeholder"]
            original = item["original_value"]
            if strategy == "mask":
                placeholder = self._mask_value(original)
            elif strategy == "remove":
                placeholder = "[REDACTED]"
            redacted_text = redacted_text[:pos] + placeholder + redacted_text[pos + length:]
            self._last_mapping[placeholder] = original
        return {"text": redacted_text, "mapping": self._last_mapping, "detected_count": len(detected)}

    def _mask_value(self, value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        elif len(value) <= 8:
            return value[:2] + "*" * (len(value) - 4) + value[-2:]
        return value[:3] + "*" * (len(value) - 6) + value[-3:]

    def restore(self, text: str, mapping: Dict[str, str]) -> str:
        restored = text
        for placeholder, original in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
            restored = restored.replace(placeholder, original)
        return restored


async def run_mcp_server():
    if not HAS_MCP:
        print("Error: MCP dependencies not installed. Run: pip install mcp", file=sys.stderr)
        sys.exit(1)
    server = Server("privacy-guard")
    guard = PrivacyGuard()

    @server.list_tools()
    async def list_tools():
        return [
            Tool(name="detect", description="Detect sensitive information in text", inputSchema={"type": "object", "properties": {"text": {"type": "string"}, "skip_validation": {"type": "boolean", "default": False}}, "required": ["text"]}),
            Tool(name="redact", description="Redact sensitive information from text", inputSchema={"type": "object", "properties": {"text": {"type": "string"}, "strategy": {"type": "string", "enum": ["placeholder", "mask", "remove"]}}, "required": ["text"]}),
            Tool(name="redact_file", description="Redact sensitive information from a file", inputSchema={"type": "object", "properties": {"file_path": {"type": "string"}, "output_path": {"type": "string"}, "strategy": {"type": "string", "default": "placeholder"}}, "required": ["file_path"]}),
            Tool(name="restore", description="Restore redacted text to original", inputSchema={"type": "object", "properties": {"text": {"type": "string"}, "mapping": {"type": "object"}}, "required": ["text", "mapping"]}),
            Tool(name="add_rule", description="Add a custom detection rule", inputSchema={"type": "object", "properties": {"name": {"type": "string"}, "pattern": {"type": "string"}, "risk_level": {"type": "string", "default": "medium"}}, "required": ["name", "pattern"]}),
            Tool(name="list_rules", description="List all detection rules", inputSchema={"type": "object", "properties": {}}),
            Tool(name="export_config", description="Export example configuration", inputSchema={"type": "object", "properties": {}}),
            Tool(name="batch_detect", description="Detect in multiple texts", inputSchema={"type": "object", "properties": {"texts": {"type": "array", "items": {"type": "string"}}}, "required": ["texts"]}),
            Tool(name="batch_redact", description="Redact from multiple texts", inputSchema={"type": "object", "properties": {"texts": {"type": "array", "items": {"type": "string"}}, "strategy": {"type": "string", "default": "placeholder"}}, "required": ["texts"]}),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        if name == "detect":
            return [TextContent(type="text", text=json.dumps(guard.detect(arguments["text"], arguments.get("skip_validation", False)), ensure_ascii=False, indent=2))]
        elif name == "redact":
            return [TextContent(type="text", text=json.dumps(guard.redact(arguments["text"], arguments.get("strategy", "placeholder")), ensure_ascii=False, indent=2))]
        elif name == "redact_file":
            return [TextContent(type="text", text=json.dumps(guard.redact_file(arguments["file_path"], arguments.get("output_path"), arguments.get("strategy", "placeholder")), ensure_ascii=False, indent=2))]
        elif name == "restore":
            return [TextContent(type="text", text=guard.restore(arguments["text"], arguments["mapping"]))]
        elif name == "add_rule":
            return [TextContent(type="text", text=json.dumps({"success": guard.add_rule(arguments["name"], arguments["pattern"], arguments.get("risk_level", "medium"))}, indent=2))]
        elif name == "list_rules":
            return [TextContent(type="text", text=json.dumps(guard.list_rules(), ensure_ascii=False, indent=2))]
        elif name == "export_config":
            return [TextContent(type="text", text=guard.export_config_example())]
        elif name == "batch_detect":
            return [TextContent(type="text", text=json.dumps(guard.batch_detect(arguments["texts"]), ensure_ascii=False, indent=2))]
        elif name == "batch_redact":
            return [TextContent(type="text", text=json.dumps(guard.batch_redact(arguments["texts"], arguments.get("strategy", "placeholder")), ensure_ascii=False, indent=2))]
        raise ValueError(f"Unknown tool: {name}")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    guard = PrivacyGuard()
    args = sys.argv[1:]
    
    output_format = "json"
    config_file = None
    clean_args = []
    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            output_format = args[i + 1]
            i += 2
        elif args[i] == "--config" and i + 1 < len(args):
            config_file = args[i + 1]
            i += 2
        else:
            clean_args.append(args[i])
            i += 1
    
    if config_file:
        result = guard.load_rules_from_config(config_file)
        if "error" in result:
            safe_print(f"Error: {result['error']}")
            sys.exit(1)
        safe_print(f"Loaded {result['total_added']} rules from {config_file}")
    
    if not clean_args:
        print(__doc__)
        print("\nAvailable commands: detect, redact, redact-file, restore, add-rule, list-rules, export-config, batch-detect, batch-redact, scan-dir")
        print("\nOptions:")
        print("  --format json|table   Output format (default: json)")
        print("  --config <file>       Load rules from JSON config file")
        sys.exit(1)
    
    cmd = clean_args[0]
    
    if cmd == "detect":
        text = " ".join(clean_args[1:]) if len(clean_args) > 1 else input("Text: ")
        results = guard.detect(text)
        if output_format == "table":
            safe_print(format_detect_table(results))
        else:
            safe_print(json.dumps(results, ensure_ascii=False, indent=2))
    elif cmd == "redact":
        text = " ".join(clean_args[1:]) if len(clean_args) > 1 else input("Text: ")
        safe_print(json.dumps(guard.redact(text), ensure_ascii=False, indent=2))
    elif cmd == "redact-file":
        output_idx = clean_args.index("--output") + 1 if "--output" in clean_args else 0
        output_path = clean_args[output_idx] if output_idx else None
        file_path = clean_args[1] if len(clean_args) > 1 else input("File path: ")
        safe_print(json.dumps(guard.redact_file(file_path, output_path), ensure_ascii=False, indent=2))
    elif cmd == "restore":
        safe_print(guard.restore(clean_args[1], json.loads(clean_args[2])))
    elif cmd == "add-rule":
        safe_print(f"Rule added: {guard.add_rule(clean_args[1], clean_args[2], clean_args[3] if len(clean_args) > 3 else 'medium')}")
    elif cmd == "list-rules":
        safe_print(json.dumps(guard.list_rules(), ensure_ascii=False, indent=2))
    elif cmd == "export-config":
        safe_print(guard.export_config_example())
    elif cmd == "batch-detect":
        safe_print(json.dumps(guard.batch_detect(["test1", "test2"]), ensure_ascii=False, indent=2))
    elif cmd == "batch-redact":
        safe_print(json.dumps(guard.batch_redact(["test1", "test2"]), ensure_ascii=False, indent=2))
    elif cmd == "scan-dir":
        directory = clean_args[1] if len(clean_args) > 1 else input("Directory: ")
        result = guard.scan_directory(directory)
        if "error" in result:
            safe_print(f"Error: {result['error']}")
            sys.exit(1)
        if output_format == "table":
            lines = [f"\n{'='*70}", f"Privacy Scan Results: {directory}", f"{'='*70}"]
            lines.append(f"Total files with sensitive data: {result['total_files']}")
            lines.append(f"Total findings: {result['total_findings']}")
            if result['high_risk_files']:
                lines.append(f"\n[!] High Risk Files ({len(result['high_risk_files'])}):")
                for f in result['high_risk_files'][:10]:
                    lines.append(f"  - {f}")
            lines.append(f"\n{'File':<40} {'Findings':<10}")
            lines.append("-" * 52)
            for f in sorted(result["files"], key=lambda x: -x["count"])[:20]:
                lines.append(f"{f['file']:<40} {f['count']:<10}")
            safe_print("\n".join(lines))
        else:
            safe_print(json.dumps(result, ensure_ascii=False, indent=2))
    elif cmd == "--mcp":
        import asyncio
        asyncio.run(run_mcp_server())
    else:
        safe_print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
