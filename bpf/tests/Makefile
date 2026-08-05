CC=clang
CFLAGS=-Wall -Werror -g -I. -I.. # the order here matters to override bpfcore
LFLAGS=
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
JAVA_REMOTE_PARENT_VECTORS ?= $(abspath $(MAKEFILE_DIR)/../../testdata/java-remote-parent-v1-vectors.txt)

sources = $(wildcard *.c)
targets = $(sources:.c=) test_java_vt_identity_disabled

all: $(targets)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LFLAGS)

test_java_vt_identity_disabled: test_java_vt_identity.c
	$(CC) $(CFLAGS) -DTEST_JAVA_REMOTE_PARENT_ENABLED=0 -o $@ $< $(LFLAGS)

.PHONY: check-java-remote-parent
check-java-remote-parent: test_java_remote_parent test_incoming_trace_collision \
	test_java_remote_parent_generation_collision test_java_remote_parent_stage \
	test_java_remote_parent_owner_reuse test_java_remote_parent_connection_close \
	test_java_remote_parent_socket_cookie test_java_remote_parent_receive \
	test_java_remote_parent_task_ancestry \
	test_java_remote_parent_stats test_java_vt_identity test_java_vt_identity_disabled \
	test_java_exit_cleanup test_java_tls_thread_mapping bpf_ssl_connection_cleanup
	./test_java_remote_parent "$(JAVA_REMOTE_PARENT_VECTORS)"
	./test_incoming_trace_collision
	./test_java_remote_parent_generation_collision
	./test_java_remote_parent_stage
	./test_java_remote_parent_owner_reuse
	./test_java_remote_parent_connection_close
	./test_java_remote_parent_socket_cookie
	./test_java_remote_parent_receive
	./test_java_remote_parent_task_ancestry
	./test_java_remote_parent_stats
	./test_java_vt_identity
	./test_java_vt_identity_disabled
	./test_java_exit_cleanup
	./test_java_tls_thread_mapping
	./bpf_ssl_connection_cleanup

.PHONY: clean
clean:
	rm -f $(targets)
