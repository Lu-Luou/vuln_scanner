CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude
LDFLAGS =
SRCDIR = src
OBJDIR = build
SRCS = $(filter-out $(SRCDIR)/winsock_test.c,$(wildcard $(SRCDIR)/*.c))
OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
TARGET = vuln_scanner

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)

run: all
	./$(TARGET)

PRINT_SRCS = $(info SRCS: $(SRCS))
