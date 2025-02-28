package utils

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed conf.yaml
var my_conf_bytes []byte

func TestGetConfItem(t *testing.T) {
	value := GetConfItem("email_addr")
	if !strings.Contains(string(my_conf_bytes), value) {
		t.Errorf("Failed to parse configuration")
	}
}
