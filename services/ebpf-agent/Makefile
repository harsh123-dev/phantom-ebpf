# Makefile for PHANTOM eBPF agent
# Builds CO-RE eBPF objects (.o) and the user-space loader (phantom-agent).
#
# Targets:
#   all       - build everything (default)
#   bpf       - compile eBPF C programs to .o with clang
#   agent     - compile user-space C loader with gcc
#   clean     - remove all build artifacts

CC      := gcc
CLANG   := clang
LLC     := llc

CFLAGS  := -Wall -Wextra -O2
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I./include

BPF_SRCS  := $(wildcard bpf/*.bpf.c)
BPF_OBJS  := $(BPF_SRCS:.bpf.c=.bpf.o)

AGENT_SRCS := cmd/main.c cmd/normalizer.c
AGENT_BIN  := phantom-agent
AGENT_LIBS := -lbpf -lelf -lz

.PHONY: all bpf agent clean

all: bpf agent

bpf: $(BPF_OBJS)

bpf/%.bpf.o: bpf/%.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

agent: $(AGENT_BIN)

$(AGENT_BIN): $(AGENT_SRCS)
	$(CC) $(CFLAGS) -I./include $^ $(AGENT_LIBS) -o $@

clean:
	rm -f bpf/*.bpf.o $(AGENT_BIN)
