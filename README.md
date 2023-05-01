# anonmap
This script was primarily developed to conduct anonymous NMAP scans under Debian 11. It install and configures "tor", "dnscrypt", "nmap" and "proxychains". All existing configuration will be stored in the script dirs backup folder. Stopping the script will revert all changes. An additional function avoidleak() is implemented to force all traffic through tor.
If everything is installed and configured the leak() function can be used to check for potential IP leaks. 
- **tor** uses the tor network for anonymization and is configured to use "DE" entry and "DE" exit notes. This country variable can be changed if desired (search for: "CHANGEME").
- **dnscrypt** is used for encrypting DNS queries before sending them into the tor network. The final destination is Cloudflare. 
- **proxychains** allows NMAP to use tor's socks4 proxy functionality due to the limited proxy capability of NMAP itself.
- (not implemented yet) tortunnel which could be used in case the NMAP scan results are unreliable. This tools uses the tor network with one hop only leading to more performance but less anonymization. 
- (not implemented yet) dnsleak test.

# Install from source
```
git clone https://github.com/shark0x00/anonmap.git
cd anonmap
chmod +x anonmap.sh
```

# Usage
```
-s, --start         starts anonmap"
-x, --stop          stops anonmap and reverts configuration"
-l, --leak          checks for potential IP leaks"
-h, --help          display this help message and exit"
```
