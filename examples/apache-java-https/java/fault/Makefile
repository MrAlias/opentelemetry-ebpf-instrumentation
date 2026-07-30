CC ?= cc
CFLAGS ?= -O2 -g
CPPFLAGS ?=
LDFLAGS ?=

WARNINGS := -std=c11 -Wall -Wextra -Werror -Wpedantic
SHIM := libobi-java-remote-parent-fault.so
TEST := getsockopt_fault_shim_test

.PHONY: all test clean

all: $(SHIM)

test: $(SHIM) $(TEST)
	./$(TEST)

$(TEST): override CPPFLAGS += -DOBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING

$(SHIM): getsockopt_fault_shim.c getsockopt_fault_shim.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC -shared -o $@ $< $(LDFLAGS) -ldl -pthread

$(TEST): getsockopt_fault_shim_test.c getsockopt_fault_shim.c getsockopt_fault_shim.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -o $@ getsockopt_fault_shim_test.c getsockopt_fault_shim.c $(LDFLAGS) -ldl -pthread

clean:
	$(RM) $(SHIM) $(TEST)
