# Privacy Guard

A tool for detecting, redacting, and restoring sensitive information.

## Features
- Detect / Batch detect
- Redact / Batch redact  
- File processing
- Luhn validation for bank cards
- China credit code validation
- Custom rules
- Directory scanning with ignore patterns
- CLI and MCP

## Supported Types
phone, email, id_card_cn, bank_card, ssn, ipv4, url, china_passport, china_credit_code, jwt_token

## Usage
```bash
# Detect sensitive info
python privacy_guard.py detect "手机号是13812345678"
python privacy_guard.py detect "手机号是13812345678" --format table

# Batch operations
python privacy_guard.py batch-detect
python privacy_guard.py batch-redact

# File processing
python privacy_guard.py redact "text with sensitive data"
python privacy_guard.py redact-file data.txt --output redacted.txt

# Custom rules
python privacy_guard.py add-rule order_id "订单号[:：]\s*([A-Z0-9]{10,20})" low
python privacy_guard.py list-rules
python privacy_guard.py export-config > rules.json

# Load rules from config
python privacy_guard.py detect "text" --config rules.json

# Directory scanning
python privacy_guard.py scan-dir ./
python privacy_guard.py scan-dir ./ --format table

# MCP server
python privacy_guard.py --mcp
''

## Options
- `--format json|table` - Output format (default: json)
- `--config <file>` - Load rules from JSON config file

## Ignore Patterns
Create `.privacy-guard-ignore` in your project directory:
```
.git
*.pyc
__pycache__
node_modules/
''

## License
MIT