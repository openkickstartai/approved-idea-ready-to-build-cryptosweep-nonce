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

func TestInlineSuppression(t *testing.T) {
	// cryptosweep:ignore suppresses the finding on the annotated line.
	code := "h = hashlib.md5(data) // cryptosweep:ignore\nh2 = hashlib.md5(data)"
	f := Scan("test.py", code)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (first line suppressed), got %d: %v", len(f), f)
	}
	if f[0].Line != 2 {
		t.Fatalf("expected finding on line 2, got line %d", f[0].Line)
	}
	if f[0].Rule.ID != "CS001" {
		t.Fatalf("expected CS001, got %s", f[0].Rule.ID)
	}

	// nolint:cryptosweep is an alternative suppression marker.
	code2 := "h = hashlib.md5(data) // nolint:cryptosweep\nh2 = hashlib.md5(data)"
	f2 := Scan("test.py", code2)
	if len(f2) != 1 {
		t.Fatalf("expected 1 finding with nolint suppression, got %d: %v", len(f2), f2)
	}
	if f2[0].Line != 2 {
		t.Fatalf("expected finding on line 2, got line %d", f2[0].Line)
	}

	// Without suppression comment both lines should fire.
	code3 := "h = hashlib.md5(data)\nh2 = hashlib.md5(data)"
	f3 := Scan("test.py", code3)
	if len(f3) != 2 {
		t.Fatalf("expected 2 findings without suppression, got %d: %v", len(f3), f3)
	}
}

func TestPartialSuppression(t *testing.T) {
	// Suppress CS001 — MD5 finding should be hidden.
	code := `h = hashlib.md5(data) // cryptosweep:ignore=CS001`
	f := Scan("test.py", code)
	if len(f) != 0 {
		t.Fatalf("expected 0 findings when CS001 suppressed, got %d: %v", len(f), f)
	}

	// Suppress a different rule (CS008) — CS001 should still fire.
	code2 := `h = hashlib.md5(data) // cryptosweep:ignore=CS008`
	f2 := Scan("test.py", code2)
	if len(f2) != 1 || f2[0].Rule.ID != "CS001" {
		t.Fatalf("expected 1 CS001 finding when only CS008 suppressed, got %d: %v", len(f2), f2)
	}

	// Line that triggers two rules: CS008 (hardcoded nonce) and CS001 (MD5).
	// Suppress only CS008 — CS001 must still be reported.
	code3 := `nonce := []byte{0x01}; h := md5.New() // cryptosweep:ignore=CS008`
	f3 := Scan("test.go", code3)
	if len(f3) != 1 {
		t.Fatalf("expected 1 finding (CS008 suppressed, CS001 remains), got %d: %v", len(f3), f3)
	}
	if f3[0].Rule.ID != "CS001" {
		t.Fatalf("expected remaining finding to be CS001, got %s", f3[0].Rule.ID)
	}

	// Suppress both rules on the same line.
	code4 := `nonce := []byte{0x01}; h := md5.New() // cryptosweep:ignore=CS008,CS001`
	f4 := Scan("test.go", code4)
	if len(f4) != 0 {
		t.Fatalf("expected 0 findings when both CS008 and CS001 suppressed, got %d: %v", len(f4), f4)
	}
}
