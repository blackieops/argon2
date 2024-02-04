package argon2

import "testing"

func TestArgon2DigestCompare(t *testing.T) {
	d := NewFromString("password123")
	if !d.Compare("password123") {
		t.Fatal("Compare did not accept valid cleartext password.")
	}
	d = NewFromString("password123")
	if d.Compare("p@ssword123") {
		t.Fatal("Compare erroneously accepted invalid cleartext password.")
	}
}

func TestNewFromEncoded(t *testing.T) {
	o := NewFromString("test")
	d, err := NewFromEncoded(o.String())
	if err != nil {
		t.Fatalf("Failed to restore valid encoded argon2 hash: %v\n", err)
	}
	if !d.Compare("test") {
		t.Fatal("NewFromEncoded restored hash that does not accept valid cleartext password.")
	}
}
