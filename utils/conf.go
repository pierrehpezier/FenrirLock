package utils

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

type T struct {
	EMAIL_ADDR string
	A          string
}

//go:embed conf.yaml
var conf_bytes []byte

func GetConfItem(name string) string {
	t := T{}
	err := yaml.Unmarshal(conf_bytes, &t)
	check(err)
	switch name {
	case "email_addr":
		return t.EMAIL_ADDR
	}
	return ""
}
