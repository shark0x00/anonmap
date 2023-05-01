#!/bin/bash
# anonmap V0.1
# Philipp Fragstein
# info@stonesec.de

# color code definition
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
RESET="\033[0m"

# global vars
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUPS_FOLDER="$SCRIPT_DIR/backups"
TOR_PORT="9040"
DNSCRYPT_CONFIG="/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
TOR_CONFIG="/etc/tor/torrc"
PROXYCHAINS_CONFIG="/etc/proxychains.conf"

logo() {
echo ""
echo " ▄▄▄       ███▄    █  ▒█████   ███▄    █  ███▄ ▄███▓ ▄▄▄       ██▓███  "
echo "▒████▄     ██ ▀█   █ ▒██▒  ██▒ ██ ▀█   █ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒"
echo "▒██  ▀█▄  ▓██  ▀█ ██▒▒██░  ██▒▓██  ▀█ ██▒▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒"
echo "░██▄▄▄▄██ ▓██▒  ▐▌██▒▒██   ██░▓██▒  ▐▌██▒▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒"
echo " ▓█   ▓██▒▒██░   ▓██░░ ████▓▒░▒██░   ▓██░▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░"
echo " ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░"
echo "  ▒   ▒▒ ░░ ░░   ░ ▒░  ░ ▒ ▒░ ░ ░░   ░ ▒░░  ░      ░  ▒   ▒▒ ░░▒ ░     "
echo "  ░   ▒      ░   ░ ░ ░ ░ ░ ▒     ░   ░ ░ ░      ░     ░   ▒   ░░       "
echo "      ░  ░         ░     ░ ░           ░        ░         ░  ░         "                                                                
}

usage() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -s, --start         starts anonmap"
    echo "  -x, --stop          stops anonmap and reverts configuration"
    echo "  -l, --leak          checks for potential IP leaks"
    echo "  -h, --help          display this help message and exit"
    echo
} 

sudocheck() {
    # check if sudo is required for executing commands
    if [ $(id -u) -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

install (){
    echo -e "${GREEN}+ SCRIPT OUTPUT: INSTALLING PACKAGES IF NOT PRESENT ${RESET}"
    local PACKAGE0="tor"
    local PACKAGE1="dnscrypt-proxy"
    local PACKAGE2="proxychains"
    local PACKAGE3="jq"
    local PACKAGE4="nmap"

    # installing packages
    echo -e "${CYAN}- SCRIPT OUTPUT: installing "$PACKAGE0" "$PACKAGE1" "$PACKAGE2" "$PACKAGE3" "$PACKAGE4" ... ${RESET}"
    sudocheck apt update
    sudocheck apt install -y "$PACKAGE0" "$PACKAGE1" "$PACKAGE2" "$PACKAGE3"
}

configure (){
    echo -e "${GREEN}+ SCRIPT OUTPUT: CONFIGURING PACKAGES IF NOT CONFIGURED YET ${RESET}"
    local DNSCRYPT_TOR_SOCKS5_PROXY="socks5://127.0.0.1:9050"
    local DNSCRYPT_FORCE_TCP=true
    local TOR_CONFIG_UPDATE=false
    local DNSCRYPT_CONFIG_UPDATE=false
    # Change TOR_ENTRY and TOR_EXIT node to optimizie the tor routing for more reliable NMAP results. 
    # CHANGEME
    local TOR_ENTRY_NODES="{de}"
    local TOR_EXIT_NODES="{de}"
    local TOR_STRICT_NODES="1"

    # error handling
    # create logs folder if it doesn't exist
    mkdir -p logs

    # set up error handling to log errors
    set -e
    trap 'echo "Error configuring packages and os. Check logs/anon_configure.log for more information." >&2; echo "Error occurred at $(date)" >> logs/anon_configure.log' ERR

    # create backups folder
    sudocheck mkdir -p "$BACKUPS_FOLDER"

    # create backups of configuration files
    echo -e "${CYAN}- SCRIPT OUTPUT: creating backups of configuration files${RESET}"
    sudocheck cp -p "$DNSCRYPT_CONFIG" "$BACKUPS_FOLDER/dnscrypt-proxy.toml.bak"
    sudocheck cp -p "$TOR_CONFIG" "$BACKUPS_FOLDER/torrc.bak"
    sudocheck cp -p "$PROXYCHAINS_CONFIG" "$BACKUPS_FOLDER/proxychains.conf.bak"
    sudocheck cp -p /etc/resolv.conf "$BACKUPS_FOLDER/resolv.conf.bak"
    sudocheck cp -p /etc/sysctl.conf "$BACKUPS_FOLDER/sysctl.conf.bak"

    # configure dnscrypt 
    echo -e "${CYAN}- SCRIPT OUTPUT: configuring dnscrypt ${RESET}"
    if grep -qE "^listen_addresses\s*=\s*\[\s*\]" "$DNSCRYPT_CONFIG"; then
        sudocheck sed -i "s/listen_addresses = \[\]/listen_addresses = \['127.0.0.1:5353'\]/g" "$DNSCRYPT_CONFIG"
        echo -e "${CYAN}- SCRIPT OUTPUT: listen_addresses updated to ['127.0.0.1:5353'] ${RESET}"
        DNSCRYPT_CONFIG_UPDATE=true
    fi
    if ! grep -q -E "^proxy\s*=" "$DNSCRYPT_CONFIG"; then
        sudocheck echo "proxy = '$DNSCRYPT_TOR_SOCKS5_PROXY'" | tee -a "$DNSCRYPT_CONFIG" > /dev/null
        DNSCRYPT_CONFIG_UPDATE=true
    fi
    if ! grep -q -E "^force_tcp\s*=" "$DNSCRYPT_CONFIG"; then
        sudocheck echo "force_tcp = $DNSCRYPT_FORCE_TCP" | tee -a "$DNSCRYPT_CONFIG" > /dev/null
        DNSCRYPT_CONFIG_UPDATE=true
    fi
    if $DNSCRYPT_CONFIG_UPDATE; then
        echo -e "${CYAN}- SCRIPT OUTPUT: dnscrypt configuration updated.${RESET}"
    else
        echo -e "${CYAN}- SCRIPT OUTPUT: no changes were made to the dnscrypt configuration.${RESET}"
    fi
    sudocheck systemctl restart dnscrypt-proxy
    sudocheck systemctl restart dnscrypt-proxy-resolvconf

    # configure /etc/resolv.conf
    echo -e "${CYAN}- SCRIPT OUTPUT: backup and configuring /etc/resolv.conf ${RESET}"
    sudocheck sh -c 'echo "nameserver 127.0.0.1" > /etc/resolv.conf'

    # configure tor
    echo -e "${CYAN}- SCRIPT OUTPUT: configuring tor ${RESET}"
    if ! grep -q "EntryNodes " "$TOR_CONFIG"; then
        echo "EntryNodes $TOR_ENTRY_NODES" | sudocheck tee -a "$TOR_CONFIG" > /dev/null
        TOR_CONFIG_UPDATE=true
    fi
    if ! grep -q "ExitNodes " "$TOR_CONFIG"; then
        echo "ExitNodes $TOR_EXIT_NODES" | sudocheck tee -a "$TOR_CONFIG" > /dev/null
        TOR_CONFIG_UPDATE=true
    fi
    if ! grep -q "StrictNodes " "$TOR_CONFIG"; then
        echo "StrictNodes $TOR_STRICT_NODES" | sudocheck tee -a "$TOR_CONFIG" > /dev/null
        TOR_CONFIG_UPDATE=true
    fi
    if ! grep -q "TransPort " "$TOR_CONFIG"; then
        echo "TransPort $TOR_PORT" | sudocheck tee -a "$TOR_CONFIG" > /dev/null
        TOR_CONFIG_UPDATE=true
    fi
    if $TOR_CONFIG_UPDATE; then
        echo -e "- ${CYAN}SCRIPT OUTPUT: tor configuration updated. restarting the tor service.${RESET}"
    else
        echo -e "${CYAN}- SCRIPT OUTPUT: no changes were made to the tor configuration.${RESET}"
    fi
    sudocheck systemctl restart tor

    # disable ipv6
    if grep -qE "net.ipv6.conf.all.disable_ipv6\s*=\s*1" /etc/sysctl.conf && grep -qE "net.ipv6.conf.default.disable_ipv6\s*=\s*1" /etc/sysctl.conf; then
        echo -e "${CYAN}- SCRIPT OUTPUT: IPv6 already disabled. No changes made.${RESET}"
    else
        echo -e "${CYAN}- SCRIPT OUTPUT: disabling ipv6${RESET}"
        echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudocheck tee -a /etc/sysctl.conf > /dev/null
        echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudocheck tee -a /etc/sysctl.conf > /dev/null
    fi
    sudocheck sysctl -p > /dev/null
}

avoidleak() {
    echo -e "${GREEN}+ SCRIPT OUTPUT: CONFIGURING IPTABLES ${RESET}"
    local TOR_UID=$(id -ur debian-tor)
    local NON_TOR="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8"

    # set up error handling to log errors
    set -e
    trap 'echo "Error configuring leak protection. Check logs/anon_avoidleak.log for more information." >&2; echo "Error occurred at $(date)" >> logs/anon_avoidleak.log' ERR

    ###################
    # IPTABLES BACKUP # 
    ###################
    # save current iptables rules to file
    iptables-save > backups/iptables.bak
    
    ##################
    # IPTABLES FLUSH # 
    ##################
    # flush default (filter) and nat table for further processing
    sudocheck iptables -F
    sudocheck iptables -t nat -F
    
    ############################
    ### IPTABLES INPUT CHAIN ###
    ############################

    # default input chain rule
    sudocheck iptables -P INPUT DROP

    # allow already established connections
    sudocheck iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # accept traffic on lo interface 
    sudocheck iptables -A INPUT -i lo -j ACCEPT
    
    ##############################
    ### IPTABLES FORWARD CHAIN ###
    ##############################

    # default forward chain rule
    iptables -P FORWARD DROP
    
    #############################
    ### IPTABLES OUTPUT CHAIN ###
    #############################

    # default output chain rule
    iptables -P OUTPUT DROP
    
    # allow loopback traffic
    iptables -A OUTPUT -o lo -j ACCEPT

    # allow established and related connections
    sudocheck iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # allow the tor process's own traffic to bypass the proxy
    sudocheck iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN

    # redirect tcp/udp dns traffic to dnscrypt 
    sudocheck iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5353
    sudocheck iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5353

    # bypass tor in case traffic gets send to local networks
    for NET in $NON_TOR; do
        sudocheck iptables -t nat -A OUTPUT -d $NET -j RETURN
    done

    # redirect all remaining tcp traffic to the tor transparent proxy port (9040).
    sudocheck iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TOR_PORT

    # allow direct connections to the local networks and loopback addresses.
    for NET in $NON_TOR; do
    sudocheck iptables -A OUTPUT -d $NET -j ACCEPT
    done

    # allow direct connections for the Tor process's own traffic.
    sudocheck iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT

    # status message
    echo -e "${CYAN}- SCRIPT OUTPUT: configuration done. Check for potential IP leaks with \"-l\" or \"--leak\"  ${RESET}"
}

leak(){
    echo -e "${GREEN}+ SCRIPT OUTPUT: CHECKING FOR POTENTIAL IP LEAK ${RESET}"

    # set up error handling to log errors
    set -e
    trap 'echo "Error checking for IP/DNS leakage. Check logs/anon_leak.log for more information." >&2; echo "Error occurred at $(date)" >> logs/anon_leak.log' ERR
    
    # ip leak check
    echo -e "${CYAN}- SCRIPT OUTPUT: checking for ip leak ${RESET}"
    echo -e "${CYAN}- SCRIPT OUTPUT: current IP is: $(curl -s -4 https://check.torproject.org/api/ip | jq .IP | cut -d "\"" -f 2) ${RESET}"
    if [[ $(curl -s -4 https://check.torproject.org/api/ip | jq .IsTor) == "true" ]]; then
        echo -e "${GREEN}! SCRIPT OUTPUT: CHECK RESULT: THIS IS A TOR IP! ${RESET}"
    else
        echo -e "${RED}! SCRIPT OUTPUT: CHECK RESULT: WARNING! THIS IS NOT A TOR IP! YOU ARE NOT ANONYMIZED! ${RESET}"
    fi
}

revert(){
    echo -e "${GREEN}+ SCRIPT OUTPUT: REVERT ALL CHANGES ${RESET}"

    # set up error handling to log errors
    set -e
    trap 'echo "Error stopping services and/or reverting configuration. Check logs/anon_revert.log for more information." >&2; echo "Error occurred at $(date)" >> logs/anon_revert.log' ERR
    
    # stop services if necessary
    sudocheck systemctl stop dnscrypt-proxy
    sudocheck systemctl stop tor

    # revert configuration
    sudocheck cp -p "$BACKUPS_FOLDER/dnscrypt-proxy.toml.bak" "$DNSCRYPT_CONFIG"
    sudocheck cp -p "$BACKUPS_FOLDER/torrc.bak" "$TOR_CONFIG"
    sudocheck cp -p "$BACKUPS_FOLDER/proxychains.conf.bak" "$PROXYCHAINS_CONFIG"
    sudocheck cp -p "$BACKUPS_FOLDER/resolv.conf.bak" /etc/resolv.conf
    sudocheck cp -p "$BACKUPS_FOLDER/sysctl.conf.bak" /etc/sysctl.conf

    # restore iptables backup
    sudocheck iptables-restore < "$BACKUPS_FOLDER/iptables.bak"

    # reload sysctl configuration
    sudocheck sysctl -p

    # delete backup directory
    sudocheck rm -r "$SCRIPT_DIR/backups/"
}

# check if no arguments are provided
if [ "$#" -eq 0 ]; then
    usage
    exit 1
fi

# process command-line arguments
while [ "$#" -gt 0 ]; do
    case "$1" in
        -s|--start)
            echo -e "${GREEN}+ STARTING ANONMAP ${RESET}"
            install
            configure
            avoidleak
            shift
            ;;
        -x|--stop)
            echo -e "${RED}+ STOPPING ANONMAP AND REVERTING CONFIGURATION ${RESET}"
            revert
            shift
            ;;
        -l|--leak)
            leak
            shift
            ;;
        -h|--help)
            logo
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            logo
            usage
            exit 1
            ;;
    esac
done
