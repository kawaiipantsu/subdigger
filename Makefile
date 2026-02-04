CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Iinclude
LDFLAGS = -lpthread -lcares -lcurl -ljson-c -lmaxminddb -lresolv

TARGET = subdigger
PREFIX ?= /usr
MANDIR ?= $(PREFIX)/share/man/man1
DATADIR ?= $(PREFIX)/share/subdigger

SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

man: man/subdigger.1

man/subdigger.1: man/subdigger.1.ronn
	ronn --roff $< > $@

install: $(TARGET) man
	install -D -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -D -m 0644 man/subdigger.1 $(DESTDIR)$(MANDIR)/subdigger.1
	install -D -m 0644 wordlists/common-subdomains.txt $(DESTDIR)$(DATADIR)/wordlists/common-subdomains.txt

clean:
	rm -f $(TARGET) $(OBJECTS) man/subdigger.1

deb: clean
	dpkg-buildpackage -us -uc -b

test: $(TARGET)
	@echo "Running basic tests..."
	./$(TARGET) --version
	./$(TARGET) --help
	@echo "Tests passed!"

.PHONY: all man install clean deb test
