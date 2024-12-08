OUTPUT_DIR=dist
LDFLAGS=""
CROSS_PLATFORMS := linux darwin windows
CROSS_ARCHITECTURES := amd64 arm64

all: build

build:
	go get
	go build -ldflags=$(LDFLAGS) -o $(OUTPUT_DIR)/

publish: LDFLAGS = "-s -w"
publish: OUTPUT_DIR = dist/release
publish: build

cross:
	@for os in $(CROSS_PLATFORMS); do \
		for arch in $(CROSS_ARCHITECTURES); do \
			output=$(OUTPUT_DIR)/$$os-$$arch; \
			make GOOS=$$os GOARCH=$$arch OUTPUT_DIR=$$output; \
		done; \
	done

clean:
	rm -rvf $(OUTPUT_DIR)

.PHONY: all build publish cross clean
