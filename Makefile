
all:
	@mkdir -p build
	GOFLAGS=-buildvcs=false GOOS=windows GOARCH=amd64 go build -o build/main.exe
	GOFLAGS=-buildvcs=false GOARCH=amd64 go build -o build/main_x86.elf
	GOFLAGS=-buildvcs=false GOARCH=arm64 go build -o build/main_arm.elf

clean:
	rm -f build/*

.PHONY: clean all