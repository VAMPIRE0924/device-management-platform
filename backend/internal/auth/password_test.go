package auth

import "testing"

func TestPasswordHashAndVerification(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") || VerifyPassword(hash, "incorrect password") {
		t.Fatal("password verification did not enforce exact password")
	}
	if _, err := HashPassword("too-short"); err == nil {
		t.Fatal("short password was accepted")
	}
}
