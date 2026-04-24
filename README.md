pi-redact
=========

A [Pi Coding Agent](https://github.com/badlogic/pi-mono) extension that automatically detects and redacts sensitive information (PII) from your prompts before they reach the main LLM.

## How it Works

```
User Prompt → pi-redact → Redacted Prompt → Main LLM
   (text)        ↓
              Local LLM + Regex
              (PII detection)

   (images)      ↓
              OCR (tesseract) + PII detection
              → blackout / describe / strip
```

1. **Regex fast-path** catches obvious patterns: emails, phone numbers, SSNs, credit cards, API keys, IP addresses
2. **Local LLM** (Ollama, LM Studio, etc.) handles semantic detection: names, addresses, contextual secrets
3. **Graceful degradation**: if the local LLM is unavailable, falls back to regex-only mode

## Installation

```bash
# Add to your Pi settings
# In ~/.pi/agent/settings.json:
{
  "packages": ["pi-redact"]
}
```

Or install manually:
```bash
npm install pi-redact
```

## Configuration

Configure via Pi's own `settings.json` under the `redact` key. Settings follow Pi's standard merge order: global (`~/.pi/agent/settings.json`) → project (`<cwd>/.pi/settings.json`) → environment variables.

### Settings

Add to your `settings.json`:

```json
{
  "redact": {
    "enabled": true,
    "host": "http://localhost:11434",
    "model": "llama3.2:3b",
    "apiFormat": "ollama",
    "timeoutMs": 15000,
    "minPromptLength": 10,
    "notifyOnRedact": true,
    "redactImages": true,
    "imageAction": "blackout",
    "imageModel": "llava",
    "categories": [
      "email", "phone", "ssn", "credit_card",
      "address", "name", "api_key", "password",
      "ip_address", "date_of_birth"
    ]
  }
}
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable redaction |
| `host` | string | `http://localhost:11434` | Local LLM endpoint URL |
| `model` | string | `llama3.2:3b` | Model name for PII detection |
| `apiFormat` | string | `ollama` | API format: `"ollama"` or `"openai"` (for LM Studio, etc.) |
| `timeoutMs` | number | `15000` | Request timeout in milliseconds |
| `minPromptLength` | number | `10` | Skip redaction for very short prompts |
| `notifyOnRedact` | boolean | `true` | Show notification when redaction occurs |
| `redactImages` | boolean | `true` | Enable image PII scanning |
| `imageAction` | string | `blackout` | Image redaction strategy: `"blackout"`, `"describe"`, or `"strip"` |
| `imageModel` | string | `llava` | Vision model for describe mode fallback |
| `categories` | string[] | all | PII categories to detect |

### Environment Variables

Environment variables override settings.json values:

| Variable | Maps to |
|----------|---------|
| `PI_REDACT_ENABLED` | `enabled` |
| `PI_REDACT_HOST` | `host` |
| `PI_REDACT_MODEL` | `model` |
| `PI_REDACT_API_FORMAT` | `apiFormat` |
| `PI_REDACT_TIMEOUT_MS` | `timeoutMs` |

### Local LLM Setup

#### Ollama (default)
```bash
# Install Ollama: https://ollama.ai
ollama pull llama3.2:3b
ollama serve  # Starts on http://localhost:11434
```

#### LM Studio
```json
{
  "redact": {
    "host": "http://localhost:1234",
    "apiFormat": "openai"
  }
}
```

#### llama.cpp server
```json
{
  "redact": {
    "host": "http://localhost:8080",
    "apiFormat": "openai"
  }
}
```

## Usage

Once installed and configured, pi-redact works automatically. When you type a prompt containing sensitive information:

```
> My email is john.doe@company.com and my SSN is 123-45-6789

🛡️ Redacted 2 sensitive item(s): email, ssn
```

The main LLM receives:
```
My email is [REDACTED_EMAIL_1] and my SSN is [REDACTED_SSN_2]
```

### Slash Commands

| Command | Description |
|---------|-------------|
| `/redact` | Show current redaction status |
| `/redact on` | Enable redaction |
| `/redact off` | Disable redaction |
| `/redact model <name>` | Change the detection model |
| `/redact host <url>` | Change the LLM endpoint |

### CLI Flag

```bash
pi --redact=false  # Disable for this session
```

## PII Categories

| Category | Detection | Examples |
|----------|-----------|---------|
| `email` | Regex + LLM | `user@example.com` |
| `phone` | Regex + LLM | `(555) 123-4567`, `+1-555-123-4567` |
| `ssn` | Regex + LLM | `123-45-6789` |
| `credit_card` | Regex + LLM | `4111-1111-1111-1111` |
| `api_key` | Regex + LLM | `sk-abc123...`, `token_xyz789...` |
| `ip_address` | Regex + LLM | `192.168.1.1` |
| `name` | LLM only | Personal names in context |
| `address` | LLM only | Physical addresses |
| `password` | LLM only | Passwords in context |
| `date_of_birth` | LLM only | Birth dates in context |

## Image Redaction

pi-redact can detect and redact PII from images attached to prompts — both clipboard-pasted images and image file paths referenced in text.

### Strategies

| Strategy | Description | Requirements |
|----------|-------------|--------------|
| `blackout` | OCR the image, detect PII, draw black boxes over sensitive regions | `uv`, `tesseract-ocr` |
| `describe` | Extract text from image, redact PII, replace image with text description | `uv` (markitdown) or vision LLM |
| `strip` | Remove the image entirely | None |

### Fallback Chain

If the required tools aren't available, pi-redact falls back gracefully:

```
blackout → describe → strip
```

### System Requirements (for image redaction)

**For `blackout` mode:**
```bash
# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install tesseract OCR
sudo apt install tesseract-ocr  # Debian/Ubuntu
brew install tesseract           # macOS
```

The Python dependencies (`pytesseract`, `pillow`) are automatically managed by `uv run` — no manual `pip install` needed.

**For `describe` mode:**
```bash
# Option 1: markitdown (via uvx)
curl -LsSf https://astral.sh/uv/install.sh | sh
# markitdown is auto-installed on first use

# Option 2: Vision LLM (via Ollama)
ollama pull llava
```

## License

MIT
