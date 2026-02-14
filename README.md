# CryptoSweep

Fast, zero-dependency cryptographic misuse scanner. Single binary, instant results.

Detects weak algorithms, hardcoded secrets, disabled TLS verification, ECB mode, weak PRNG usage, and timing-unsafe comparisons across 12 languages.

## Install

```bash
go install github.com/openkickstart/cryptosweep@latest
```

Or build from source:

```bash
git clone https://github.com/openkickstart/cryptosweep.git
cd cryptosweep
go build -o cryptosweep .
```

## Usage

```bash
# Scan current directory
./cryptosweep .

# Scan a specific path
./cryptosweep /path/to/project
```

Exit code `0` = clean, `1` = issues found.

## Rules

| ID    | Name                    | Severity | CWE     |
|-------|-------------------------|----------|---------|
| CS001 | Weak hash: MD5          | HIGH     | CWE-328 |
| CS002 | Weak hash: SHA-1        | HIGH     | CWE-328 |
| CS003 | Weak cipher: DES/RC4    | CRITICAL | CWE-327 |
| CS004 | ECB mode                | CRITICAL | CWE-327 |
| CS005 | Hardcoded secret        | CRITICAL | CWE-798 |
| CS006 | TLS verify disabled     | CRITICAL | CWE-295 |
| CS007 | Weak PRNG               | MEDIUM   | CWE-338 |
| CS008 | Hardcoded IV/nonce      | HIGH     | CWE-329 |
| CS009 | Weak RSA key (<2048)    | HIGH     | CWE-326 |
| CS010 | Timing-unsafe compare   | MEDIUM   | CWE-208 |

## CI Integration

Add to your GitHub Actions workflow:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-go@v5
  with:
    go-version: '1.22'
- run: go install github.com/openkickstart/cryptosweep@latest
- run: cryptosweep .
```

## Performance

Zero external dependencies. Pre-compiled regexes. Scans 100k+ LOC in under 1 second.

## License

MIT
