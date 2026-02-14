package main

import (
	"regexp"
	"strings"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
)

type Rule struct {
	ID       string
	Name     string
	Pattern  *regexp.Regexp
	Severity Severity
	CWE      string
}

type Finding struct {
	Rule  Rule
	File  string
	Line  int
	Match string
}

var Rules = []Rule{
	{"CS001", "Weak hash: MD5", regexp.MustCompile(`(?i)(?:md5\.New|hashlib\.md5|getInstance\(\s*"MD5"|createHash\(\s*['"]md5['"])`), High, "CWE-328"},
	{"CS002", "Weak hash: SHA-1", regexp.MustCompile(`(?i)(?:sha1\.New|hashlib\.sha1|getInstance\(\s*"SHA-?1"|createHash\(\s*['"]sha1['"])`), High, "CWE-328"},
	{"CS003", "Weak cipher: DES/RC4", regexp.MustCompile(`(?i)(?:des\.NewCipher|DES/|[^a-z]RC4[^a-z]|ARC4|Blowfish)`), Critical, "CWE-327"},
	{"CS004", "ECB mode", regexp.MustCompile(`(?i)(?:AES/ECB|MODE_ECB|NewECBEncrypter|NewECBDecrypter)`), Critical, "CWE-327"},
	{"CS005", "Hardcoded secret", regexp.MustCompile(`(?i)(?:secret|api[_-]?key|password|private[_-]?key)\s*[:=]\s*["'][^\s"']{6,}["']`), Critical, "CWE-798"},
	{"CS006", "TLS verify disabled", regexp.MustCompile(`(?i)(?:InsecureSkipVerify\s*[:=]\s*true|verify\s*=\s*False|REJECT_UNAUTHORIZED.*['"]0['"]|CERT_NONE)`), Critical, "CWE-295"},
	{"CS007", "Weak PRNG", regexp.MustCompile(`(?:math/rand|math\.rand\b|random\.randint|Math\.random\(\))`), Medium, "CWE-338"},
	{"CS008", "Hardcoded IV/nonce", regexp.MustCompile(`(?i)(?:iv|nonce)\s*[:=]\s*(?:["'][0-9a-f]{8,}["']|\[\]byte\{)`), High, "CWE-329"},
	{"CS009", "Weak RSA key (<2048)", regexp.MustCompile(`(?i)(?:GenerateKey\([^,]+,\s*(?:512|768|1024)\)|key_size\s*=\s*(?:512|768|1024))`), High, "CWE-326"},
	{"CS010", "Timing-unsafe compare", regexp.MustCompile(`(?i)\b(?:hmac|mac|digest|signature)\b[^(]*(?:==|!=)`), Medium, "CWE-208"},
}

// parseSuppression checks a source line for inline suppression comments.
// It returns (suppressAll, suppressedRuleIDs).
//   - // cryptosweep:ignore  or  // nolint:cryptosweep  → suppress all rules
//   - // cryptosweep:ignore=CS001,CS008              → suppress only listed IDs
func parseSuppression(line string) (bool, map[string]bool) {
	// // nolint:cryptosweep always suppresses every rule on the line.
	if strings.Contains(line, "// nolint:cryptosweep") {
		return true, nil
	}

	idx := strings.Index(line, "// cryptosweep:ignore")
	if idx == -1 {
		return false, nil
	}

	rest := line[idx+len("// cryptosweep:ignore"):]

	// Nothing after the marker, or only whitespace → suppress all.
	if len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\r' {
		return true, nil
	}

	// Rule-specific suppression: // cryptosweep:ignore=CS001,CS008
	if rest[0] == '=' {
		idsPart := rest[1:]
		// Stop at first whitespace so trailing comments are ignored.
		if sp := strings.IndexAny(idsPart, " \t\r"); sp != -1 {
			idsPart = idsPart[:sp]
		}
		tokens := strings.Split(idsPart, ",")
		m := make(map[string]bool, len(tokens))
		for _, tok := range tokens {
			if id := strings.TrimSpace(tok); id != "" {
				m[id] = true
			}
		}
		if len(m) > 0 {
			return false, m
		}
	}

	return false, nil
}

// Scan analyses the content of a single file and returns all findings.
func Scan(filename, content string) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		suppressAll, suppressIDs := parseSuppression(line)
		if suppressAll {
			continue
		}
		for _, rule := range Rules {
			if rule.Pattern.MatchString(line) {
				if len(suppressIDs) > 0 && suppressIDs[rule.ID] {
					continue
				}
				findings = append(findings, Finding{
					Rule:  rule,
					File:  filename,
					Line:  i + 1,
					Match: line,
				})
			}
		}
	}
	return findings
}
