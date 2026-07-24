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
check-java-remote-parent: test_java_remote_parent test_incoming_trace_collision \
	test_java_remote_parent_generation_collision test_java_remote_parent_stage \
	test_java_remote_parent_owner_reuse test_java_remote_parent_connection_close \
	test_java_remote_parent_stats bpf_ssl_connection_cleanup
	./test_java_remote_parent "$(JAVA_REMOTE_PARENT_VECTORS)"
	./test_incoming_trace_collision
	./test_java_remote_parent_generation_collision
	./test_java_remote_parent_stage
	./test_java_remote_parent_owner_reuse
	./test_java_remote_parent_connection_close
	./test_java_remote_parent_stats
	./bpf_ssl_connection_cleanup

.PHONY: clean
clean:
	rm -f $(targets)
