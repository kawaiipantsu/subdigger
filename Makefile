CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Iinclude
LDFLAGS = -lpthread -lcares -lcurl -ljson-c -lmaxminddb -lresolv

TARGET = subdigger
PREFIX ?= /usr
MANDIR ?= $(PREFIX)/share/man/man1
DATADIR ?= $(PREFIX)/share/subdigger

SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all man install clean deb test refresh-wordlists

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
	mkdir -p $(DESTDIR)$(DATADIR)/wordlists
	install -m 0644 wordlists/*.txt $(DESTDIR)$(DATADIR)/wordlists/

refresh-wordlists:
	@echo "==> Refreshing system wordlists in $(DESTDIR)$(DATADIR)/wordlists/"
	@echo "==> Removing old wordlists from $(DESTDIR)$(DATADIR)/wordlists/..."
	@if [ -d "$(DESTDIR)$(DATADIR)/wordlists" ]; then \
		rm -fv $(DESTDIR)$(DATADIR)/wordlists/*.txt; \
	else \
		echo "    Directory does not exist yet, will be created."; \
	fi
	@echo "==> Creating wordlists directory..."
	@mkdir -pv $(DESTDIR)$(DATADIR)/wordlists
	@echo "==> Copying fresh wordlists from source..."
	@for wordlist in wordlists/*.txt; do \
		echo "    Installing $$wordlist"; \
		install -m 0644 "$$wordlist" "$(DESTDIR)$(DATADIR)/wordlists/"; \
	done
	@echo "==> Wordlist refresh complete!"
	@echo "==> Note: Custom wordlists in ~/.config/subdigger/ or ~/ are preserved."

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
