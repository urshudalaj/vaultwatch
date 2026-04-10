# vaultwatch

A CLI tool that monitors HashiCorp Vault secret expiry and sends alerts before leases expire.

---

## Installation

```bash
go install github.com/yourusername/vaultwatch@latest
```

Or build from source:

```bash
git clone https://github.com/yourusername/vaultwatch.git
cd vaultwatch
go build -o vaultwatch .
```

---

## Usage

Set your Vault address and token, then run vaultwatch with a warning threshold:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="s.yourtoken"

# Alert on secrets expiring within 48 hours
vaultwatch --threshold 48h --alert slack
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--threshold` | Warn when lease expires within this duration | `24h` |
| `--alert` | Alert method: `stdout`, `slack`, `email` | `stdout` |
| `--interval` | How often to poll Vault | `5m` |
| `--config` | Path to config file | `~/.vaultwatch.yaml` |

### Config File Example

```yaml
vault_addr: https://vault.example.com
threshold: 48h
alert: slack
slack_webhook: https://hooks.slack.com/services/xxx/yyy/zzz
interval: 10m
```

---

## Requirements

- Go 1.21+
- HashiCorp Vault 1.12+

---

## License

This project is licensed under the [MIT License](LICENSE).