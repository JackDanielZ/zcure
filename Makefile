SUDO_USER = $(shell stat -c %U .)
SERVICEDIR = /etc/systemd/system

install:
	mkdir -p $(PREFIX)/bin/
	install *.py $(PREFIX)/bin/
	install -m 644 service/*.service $(SERVICEDIR)
	for service in `ls -1 service/*.service`; do \
		sed -i 's|\$$USER|$(SUDO_USER)|g' $(SERVICEDIR)/`basename $$service`; \
	done
	# Optional: Reload systemd
	systemctl daemon-reload

