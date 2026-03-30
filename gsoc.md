# PII-Safe

## Privacy Middleware & MCP Plugin for Agentic AI Systems

### Overview

PII-Safe is a privacy layer designed for AI systems that process sensitive data. It detects, manages, and sanitizes personally identifiable information (PII) before it reaches LLMs, logs, or storage systems.

It helps prevent data leakage and ensures compliance with standards like GDPR and HIPAA.

### Problem

AI agents often process data containing:

- Emails
- IP addresses
- Phone numbers
- Usernames
- Customer IDs

Without proper handling, this sensitive data can leak into:

- LLM prompts
- Logs
- Memory systems

PII-Safe solves this by adding a policy-driven privacy layer.

### Features

#### PII Detection
- Works on both structured JSON and free text
- Detects emails, IPs, phone numbers, names, etc.

#### Policy Engine
- Define rules using YAML
- Actions:
  - Allow
  - Redact
  - Pseudonymize
  - Block

#### Sanitization Engine
- Redaction ([EMAIL_REDACTED])
- Pseudonymization (consistent tokens like USER_01)
- Privacy risk scoring

#### Audit Logging
- Tracks all transformations
- Supports compliance and debugging

#### FastAPI Middleware
- Easy integration with existing systems

#### MCP Server
- Works with LangChain, LangGraph, AutoGen, etc.

#### CLI Tool
- Batch processing for JSON, CSV, and text files

### Architecture

The system follows this pipeline:

Input → PII Detection → Policy Engine → Sanitization → Output + Audit Log

(As shown in the architecture diagram in the document)

### Example Policy
```
policies:
  - name: pseudonymize_emails
    entity_types: [EMAIL]
    action: pseudonymize

  - name: block_export
    entity_types: [EMAIL, PHONE]
    action: block
```

### API Endpoints
- /sanitize – sanitize a single payload
- /batch – process bulk data
- /policy – manage policies
- /audit – fetch audit logs

### MCP Tools
- pii_sanitize_text
- pii_sanitize_json
- pii_check_policy
- pii_get_audit_log
- pii_configure_policy

### CLI Usage
```
piisafe sanitize --input logs.jsonl --operation export --output sanitized.jsonl
```

### Tech Stack
- Python
- FastAPI
- LangGraph
- Redis (token mapping)
- Pydantic
- spaCy / HuggingFace (NER)

### Use Cases
- AI agents processing logs or chats
- Security and incident analysis systems
- Enterprise LLM pipelines
- Compliance-sensitive applications

### Project Timeline
- Phase 1: Detection & Policy
- Phase 2: Sanitization & API
- Phase 3: MCP & CLI
- Phase 4: Testing & Documentation

### Author

Janvi Jaivir Singh
GitHub: https://github.com/janvis11