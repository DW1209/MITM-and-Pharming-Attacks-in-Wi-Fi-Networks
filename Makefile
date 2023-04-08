MITM  = mitm_attack
PHARM = pharm_attack

all: $(MITM) $(PHARM)
	chmod +x $^

clean:
	chmod -x $(MITM) $(PHARM)