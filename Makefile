MITM  = mitm_attack
PHARM = pharm_attack

MITM_FILE  = mitm_attack.py
PHARM_FILE = pharm_attack.py

all: $(MITM) $(PHARM)

$(MITM): $(MITM_FILE)
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -t nat -F
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
	cp $< $@ && chmod +x $@

$(PHARM): $(PHARM_FILE)
	cp $< $@ && chmod +x $@

clean:
	rm $(MITM) $(PHARM)