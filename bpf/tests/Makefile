CC=clang
CFLAGS=-Wall -Werror -g -I. -I.. # the order here matters to override bpfcore
LFLAGS=
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
JAVA_REMOTE_PARENT_VECTORS ?= $(abspath $(MAKEFILE_DIR)/../../testdata/java-remote-parent-v1-vectors.txt)

sources = $(wildcard *.c)
targets = $(sources:.c=)

all: $(targets)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LFLAGS)

.PHONY: check-java-remote-parent
check-java-remote-parent: test_java_remote_parent
	./test_java_remote_parent "$(JAVA_REMOTE_PARENT_VECTORS)"

.PHONY: clean
clean:
	rm -f $(targets)
