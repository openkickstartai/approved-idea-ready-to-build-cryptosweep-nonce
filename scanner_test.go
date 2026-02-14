package main

import "testing"

func TestDetectsMD5(t *testing.T) {
	f := Scan("app.py", `h = hashlib.md5(data)`)
	if len(f) != 1 || f[0].Rule.ID != "CS001" {
		t.Fatalf("expected 1 CS001 finding, got %d %v", len(f), f)
	}
	if f[0].Line != 1 {
		t.Fatalf("expected line 1, got %d", f[0].Line)
	}
}

func TestDetectsSHA1(t *testing.T) {
	f := Scan("main.go", `h := sha1.New()`)
	if len(f) != 1 || f[0].Rule.ID != "CS002" {
		t.Fatalf("expected 1 CS002 finding, got %d %v", len(f), f)
	}
}

func TestDetectsTLSSkipVerify(t *testing.T) {
	f := Scan("client.go", `cfg := &tls.Config{InsecureSkipVerify: true}`)
	if len(f) != 1 || f[0].Rule.ID != "CS006" {
		t.Fatalf("expected 1 CS006 finding, got %d %v", len(f), f)
	}
}

func TestDetectsHardcodedSecret(t *testing.T) {
	f := Scan("config.py", `api_key = "sk_live_abc123def456"`)
	if len(f) != 1 || f[0].Rule.ID != "CS005" {
		t.Fatalf("expected 1 CS005 finding, got %d %v", len(f), f)
	}
}

func TestDetectsECBMode(t *testing.T) {
	f := Scan("crypto.py", `cipher = AES.new(key, AES.MODE_ECB)`)
	if len(f) != 1 || f[0].Rule.ID != "CS004" {
		t.Fatalf("expected 1 CS004 finding, got %d %v", len(f), f)
	}
}

func TestDetectsWeakRSA(t *testing.T) {
	f := Scan("gen.go", `key, _ := rsa.GenerateKey(rand.Reader, 1024)`)
	if len(f) != 1 || f[0].Rule.ID != "CS009" {
		t.Fatalf("expected 1 CS009 finding, got %d %v", len(f), f)
	}
}

func TestDetectsHardcodedNonce(t *testing.T) {
	f := Scan("enc.go", `nonce := "aabbccdd11223344"`)
	if len(f) != 1 || f[0].Rule.ID != "CS008" {
		t.Fatalf("expected 1 CS008 finding, got %d %v", len(f), f)
	}
}

func TestNoFalsePositiveOnSafeCode(t *testing.T) {
	code := "h := sha256.New()\nh.Write(data)\nresult := h.Sum(nil)"
	f := Scan("safe.go", code)
	if len(f) != 0 {
		t.Fatalf("expected 0 findings on safe code, got %d: %v", len(f), f)
	}
}

func TestMultipleFindings(t *testing.T) {
	code := "h = hashlib.md5(data)\npassword = \"supersecret123\""
	f := Scan("bad.py", code)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(f), f)
	}
	if f[0].Line != 1 || f[1].Line != 2 {
		t.Fatalf("expected lines 1,2 got %d,%d", f[0].Line, f[1].Line)
	}
}

func TestVerifyDisabledPython(t *testing.T) {
	f := Scan("req.py", `requests.get(url, verify=False)`)
	if len(f) != 1 || f[0].Rule.ID != "CS006" {
		t.Fatalf("expected 1 CS006 finding, got %d %v", len(f), f)
	}
}
