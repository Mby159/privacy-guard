# Privacy Guard

A tool for detecting, redacting, and restoring sensitive information.

## Features
- Detect / Batch detect
- Redact / Batch redact  
- File processing
- Luhn validation for bank cards
- China credit code validation
- Custom rules
- CLI and MCP

## Supported Types
phone, email, id_card_cn, bank_card, ssn, ipv4, url, china_passport, china_credit_code, jwt_token

## Usage
python privacy_guard.py detect " text\
python privacy_guard.py batch-detect
python privacy_guard.py redact \text\
python privacy_guard.py redact-file data.txt --output redacted.txt
python privacy_guard.py add-rule name pattern risk_level

## License
MIT