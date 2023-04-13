# MITM and Pharming Attacks in Wi-Fi Networks

## Description
### MITM Attack
- Print out the IP/MAC addresses of all the Wi-Fi devices or VMs except for Attacker and AP/Host
- Print out the username and password which a user submits to the [website](https://e3.nycu.edu.tw/login/index.php) using any of the Wi-Fi devices or VMs
### Pharminig Attack
- Print out the IP/MAC addresses of all the Wi-Fi devices or VMs except for Attacker and AP/Host
- Redirect the [NYCU home page](http://www.nycu.edu.tw) to the [phishing page](http://140.113.207.241)

## Execution
### Build
Perpare two machines, attacker and victim, and type the command in the attacker machine.
```bash
$ make
```
### MITM Attack
Start the MITM attack via the command in the attacker machine.
```bash
$ sudo ./mitm_attack
```
Open a private window in web browser and enter https://e3.nycu.edu.tw/login/index.php in the victim machine.
### Pharming Attack
Start the pharming attack via the command in the attacker machine.
```bash
$ sudo ./pharm_attack
```
Open a private window in web browser and enter http://www.nycu.edu.tw in the victim machine.