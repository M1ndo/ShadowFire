#!/bin/bash

# Written by ybenel
# Good Luck on your folish acts.

# Colors:
Italic='\e[3m'
Normal='\e[0m'
Bold='\e[1m'

Red='\e[0;31m'       
Green='\e[0;32m'     
Yellow='\e[0;33m'    
Mage='\e[0;34m'      
Purple='\e[0;35m'    
Blue='\e[0;36m'      
White='\e[0;37m'     
Orange='\e[0;202m]'

Red2='\e[1;31m'       
Green2='\e[1;32m'     
Yellow2='\e[1;33m'    
Mage2='\e[1;34m'      
Purple2='\e[1;35m'    
Blue2='\e[1;36m'      
White2='\e[1;37m' 

TEMP_FILE=/tmp/.nikdt
DNSCRYPT_FILE=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
DNSCRYPT_FILE_BK=/etc/dnscrypt-proxy/dnscrypt-proxy.toml.bk
TORC_FILE=/etc/tor/torrc
TORC_FILE_BK=/etc/tor/torrc.bk
NETWORK_CONF=/etc/NetworkManager/conf.d/
NET_DNS=/tmp/dns.conf
DNS_RESOLVE=/etc/resolv_me.conf
DNSSET=$(grep 'libredns dct-de1' $DNSCRYPT_FILE 2>/dev/null)
TORSET=$(grep 'SocksPolicy accept 127.0.0.1' $TORC_FILE 2>/dev/null)
TOR_SERVICE=tor.service
DNS_SERVICE=dnscrypt-proxy.service
UFW_USER=/etc/ufw/user.rules
SYSCTL_TCP=/etc/sysctl.d/99-sysctl.conf
# Read from environment
SETDNS=
SETTOR=
SS_ON=${SS_ON:-""}
I_PORTS=${O_PORTS:-""}
FORCE_TCP=${FORCE_TCP:-""}
TOR_START=${TOR_START:-""}
MAC_CHANGE=${MAC_CHANGE:-""}
RESET_MAC=${RESET_MAC:-""}
ZONE_RESET=${ZONE_RESET:-""}
SYSCTL_NET=${SYSCTL_NET:-""}
UFW_SET=${UFW_SET:-""}
REF_C=${REF_C:-"-c germany,france,spain,portugal"}


trap ctrl_c INT
ctrl_c () {
  printf "$Red[!]$Yellow2 Exiting.....\n"
  exit 1
}

function check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
   printf "$Red[!]$RESET Script requires root !\n"
   exit 1
  fi
}


function compatibility() { 
  DISTRO=$(pacman -h 2>/dev/null)
  if [[ -z ${DISTRO} ]]; then
    printf "$Green[+]$Normal This Script is only compatible with$Purple Arch Based\n"
    exit 1;
  fi
}

function check_live() {
  user=$(grep liveuser /etc/passwd)
  if [[ -n $user ]]; then
    printf "$Green2[+]$Normal Dectecting Liveuser Environment.\n"
    if pacman -Qs ufw >/dev/null; then
      printf "$Purple[+]$Normal Already Ran? Skipping.\n"
    else
      printf "$Blue2[+]$Normal Updating & Installing Glibc\n"
      reflector --download-timeout 15 --protocol https --latest 15 --number 10 --sort rate $REF_C --verbose --save /etc/pacman.d/mirrorlist
      pacman -Sy && pacman -S --noconfirm archlinux-keyring blackarch-keyring && pacman -S --noconfirm glibc ufw 
      cp -r /usr/lib/python3.10/site-packages/ufw* /usr/lib/python3.9/site-packages/
    fi
  fi
}

function get_lip() {
  IPS=$(ip r s | grep default | awk '{print $9}')
  echo $IPS
} 


function dns_service() { 
  SERVICE=$(systemctl is-active $DNS_SERVICE)
  if [[ $SERVICE == "inactive" ]]; then
    printf "$Blue[-]$Normal$Bold DNSCrypt$Normal Is Inactive\n"
    check_dns
    printf "$Green[+]$Normal Starting And Enabling$Bold DNSCrypt$Normal\n"
    systemctl enable $DNS_SERVICE && systemctl start $DNS_SERVICE
  else
    printf "$Purple[-]$Normal$Bold DNSCrypt$Normal Is Active\n"
    check_dns
    [[ ! $SETDNS -eq 0 ]] && printf "$Yellow[+]$Normal$Bold Continuing$Normal\n" || printf "$Green[+]$Normal Starting And Enabling$Bold DNSCrypt$Normal\n" && systemctl enable $DNS_SERVICE && systemctl restart $DNS_SERVICE
  fi
}

function download_file() {
  curl_path=$(which curl 2>/dev/null)
  if [[ $curl_path != '' ]];then
    curl -s --output $2 $1
  else
    if [ -e $2 ]; then
      rm $2
    fi
    wget -qO $2 $1 2>/dev/null || printf "$Red[!]$Normal Nor$Bold Wget$Normal or$Bold Curl$Normal Was found!\n";exit 1
  fi
}

function dw_dnsconfig() { 
  printf "$Green[+]$Normal Downloading$Bold$Blue2 Dnscrypt$Normal Config\n"
  download_file "https://0x0.st/oUqr.toml" $DNSCRYPT_FILE
}

function dw_torrc() { 
  printf "$Green[+]$Normal Downloading$Bold$Blue2 Tor$Normal Config\n"
  download_file "https://0x0.st/oUr8.txt" $TORC_FILE
}


function check_dns() { 
  if [[ $DNSSET == '' ]]; then
    printf "$Red[-]$Normal $Bold$Purple2 DNS Crypt$Normal Is Not Setup\n"
    printf "$Green[+]$Normal Setting up dns\n"
    if [ -e $DNSCRYPT_FILE ]; then
      printf "$Blue2[+]$Normal Backing up current config file\n"
      mv $DNSCRYPT_FILE $DNSCRYPT_FILE_BK
      dw_dnsconfig
    else
      printf "$Yellow[-]$Normal Config file doesn't exist. Continuing Anyways.\n"
      dw_dnsconfig
    fi
    SETDNS=0
    printf "$Bold"
    echo "|-----------------------------------------------------|"
    echo "|          Finished Setting up DNSCrypt               |"
    echo "|-----------------------------------------------------|"
    printf "$Normal"
  else
    printf "$Green[+]$Normal Configuration Already Set\n"
    SETDNS=1
  fi
  set_dns
}

function tor_service() { 
  SERVICE=$(systemctl is-active tor.service)
  if [[ $SERVICE == "inactive" ]]; then
    printf "$Blue[-]$Normal$Bold Tor$Normal Is Inactive\n"
    tor_setup
    if [[ $TOR_START == "" || $TOR_START == "on" ]]; then
      printf "$Green[+]$Normal Starting$Bold Tor$Normal\n"
      systemctl start $TOR_SERVICE
    else
      printf "$Mage2[-]$Normal Not Starting$Bold Tor$Normal\n"
    fi
  else
    printf "$Purple[-]$Normal$Bold Tor$Normal Is Active\n"
    tor_setup
    [[ ! $SETTOR -eq 0 ]] && printf "$Yellow[+]$Normal$Bold Continuing$Normal\n" || printf "$Green[+]$Normal Starting$Bold Tor$Normal\n" && systemctl restart $TOR_SERVICE
  fi
}

function tor_setup() { 
  if [[ $TORSET == '' ]]; then
    printf "$Mage2[X]$Normal Sleeping For 2 Seconds To Let DNS Start\n"
    sleep 2
    printf "$Red[-]$Normal $Bold$Purple2 Tor$Normal Is Not Setup\n"
    printf "$Green[+]$Normal Setting up$Bold Tor$Normal\n"
    if [ -e $TORC_FILE ]; then
      printf "$Blue2[+]$Normal Backing up current config file\n"
      mv $TORC_FILE $TORC_FILE_BK
      dw_torrc
      tor_config
    else
      printf "$Yellow[-]$Normal Config file doesn't exist. Continuing Anyways.\n"
      dw_torrc
      tor_config
    fi
    SETTOR=0
  else
    printf "$Green[+]$Normal Configuration Already Set\n"
    SETTOR=1
  fi
}


function change_bridges() {
  # Addon to change bridges because i'll need it at some point
  printf "$Purple2[+]$Normal Please Visit$Bold https://bridges.torproject.org/bridges/?transport=obfs4$Normal\n"
  printf "$Green2[+]$Normal Input Selected$Bold Bridges$Normal Then do CTRL+D: "
  readarray -t bridges
  printf "$Blue2[+]$Normal Adding Selected$Bold Bridges$Normal\n"
  unset "bridges[3]"
  for br in "${!bridges[@]}"; do
    bridge="${bridges[br]}"
    echo "Bridge ${bridge}" >> $TORC_FILE
  done
}



function tor_config() { 
  printf "$Blue2[+]$Normal Modifying$Bold$Green Tor$Normal Configuration\n"
  IP=$(get_lip)
  printf "$Green2[!]$Normal Please Input A$Bold Strong$Red Tor$Normal Control Password: "
  read -r password
  printf "$Green2[!]$Normal Please A Nickname With No Spaces For$Bold$Red Tor$Normal To Use: "
  read -r nickname
  PASS=$(sudo -u tor tor --hash-password "$password")
  printf "$Purple2[+]$Normal Changing$Bold$Green Tor$Normal Control Password\n"
  printf "$Yellow[+]$Normal Generate Hashed Password Using$Bold %s :: %s$Normal\n" "${password}" "${PASS}"
  sed -i "s/16:7EF32549F6E2416D60BBF4EE0E91BA198A465CFDF60647D6BC5B8DFEDE/$PASS/g" $TORC_FILE
  printf "$Blue2[+]$Normal Found$Yellow$Bold %s$Normal IPs\n" "${IP}"
  sed -i "/SocksPolicy accept 192.168.1.110/d" $TORC_FILE
  for ips in $IP; do
    printf "$Blue2[+]$Normal Adding$Bold$Green %s$Normal To$Bold$Purple2 Tor$Normal Config\n" "${ips}"
    sed -i "/SocksPolicy accept 127.0.0.1/a\SocksPolicy accept ${ips}" $TORC_FILE
  done
  printf "$Purple2[+]$Normal Changing$Bold$Green Tor$Normal Nickname\n"
  sed -i "s/JackTheRipper/${nickname}/g" $TORC_FILE
  printf "$Green2[+]$Normal Do You Wanna Use$Bold Bridges$Normal[y/N]: "
  read -r answer
  if [[ $answer == 'y' || $answer == "Y" ]];then
    change_bridges
  else
    printf "$Red[-]$Normal Not$Bold$Yellow2 Adding$Normal Bridges Skipping ...\n"
    sed -i "s/UseBridges 1/#UseBridges 1/g" $TORC_FILE
    sed -i "s/ClientTransportPlugin obfs4 exec \/usr\/bin\/obfs4proxy managed/#ClientTransportPlugin obfs4 exec \/usr\/bin\/obfs4proxy managed/g" $TORC_FILE
  fi 
  printf "$Bold"
  echo "|-----------------------------------------------------|"
  echo "|              Finished Setting up Tor                |"
  echo "|-----------------------------------------------------|"
  printf "$Normal"
}


function wipe() {
  printf "$Red2[+]$Normal Doing Cleaning For You ...\n"
  echo 1024 >/proc/sys/vm/min_free_kbytes
  echo 3 >/proc/sys/vm/drop_caches
  echo 1 >/proc/sys/vm/oom_kill_allocating_task
  echo 1 >/proc/sys/vm/overcommit_memory
  echo 0 >/proc/sys/vm/oom_dump_tasks
  smem-secure-delete -fllv
}

function check_require() {
  # Check if necessary packages are installed.
  progs=("tor" "torsocks" "obfs4proxy" "dnscrypt-proxy" "secure-delete" "ufw" "macchanger")
  optional=("nyx" "proxychains-ng")
  optional2=("Command line status monitor for tor" "Redirect traffic via proxy")
  echo "|-----------------------------------------------------|"
  echo "|          Checking For Necessary Packages            |"
  echo "|  Installing If Necessary Packages Are Not Installed |"
  echo "|-----------------------------------------------------|"
  for a in "${progs[@]}"; do
    if pacman -Qs $a >/dev/null; then
      printf "$Purple[+]$Normal Package $Blue$Bold$a$Normal is$Green$Italic installed$Normal\n"
    else
      touch $TEMP_FILE
      printf "$Red[!]$Normal Package $Blue$Bold$a$Normal is$Red$Italic not installed$Normal\n"
      printf "$Yellow[+]$Normal Installing $Purple$a$Normal\n"
      yes | pacman -S --noconfirm $a && if [ -f $TEMP_FILE ]; then rm $TEMP_FILE;fi
    fi
  done
  [ -f $TEMP_FILE ] && check_require && rm $TEMP_FILE
  echo "|-----------------------------------------------------|"
  echo "|          Checking For Optional Packages             |"
  echo "|-----------------------------------------------------|" 
  for b in "${!optional[@]}"; do
    ch_pkg=$(pacman -Qk ${optional[b]} &>/dev/null)
    if [[ $? -eq 0 ]]; then
      printf "$Purple[+]$Normal Package $Blue$Bold%s$Normal is$Green$Italic installed$Normal\n" "${optional[b]}"
    else
      printf "$Purple2[!]$Normal Package $Blue2$Bold%s$Normal :: $Bold%s$Normal is$Red$Italic not installed$Normal\n" "${optional[b]}" "${optional2[b]}"
      printf "\e[1;31m[!]\e[1;32m Do You Want To Install It:\e[1;36m[Y:n]:>\e[1;31m"  
      read -r answer
      if [[ $answer == 'y' || $answer == "Y" ]];then
        pacman -S ${optional[b]}
      fi
    fi
  done
}

function p_error() { 
  if [ ! $1 -eq 0 ]; then
    printf "$Red[+]$Normal Error Happend ${2}\n" >&2;exit 1
  fi
}

function set_dns() { 
  if [ ! -f $NETWORK_CONF/dns.conf ]; then
    printf "$Blue2[+]$Normal Changing Up Default DNS Name Servers.\n"
    download_file "https://0x0.st/oUqo.conf" $DNS_RESOLVE 
    download_file "https://0x0.st/oUqH.conf" $NET_DNS
    [ -f /etc/resolv.conf ] && mv /etc/resolv.conf /etc/resolve.conf.old
    [ ! -d $NETWORK_CONF ] && mkdir -p $NETWORK_CONF
    ln -s $DNS_RESOLVE /etc/resolv.conf
    p_error $? "When Symlinking ${DNS_RESOLVE} to /etc/resolv.conf"
    mv $NET_DNS $NETWORK_CONF
    p_error $? "When Moving ${NET_DNS} to ${NETWORK_CONF}"
    printf "$Mage2[+]$Normal Finished Up With DNS.\n"
    printf "$Green2[-]$Normal Restarting NetworkManager.\n"
    systemctl restart NetworkManager
  else
    printf "$Blue2[+]$Normal$Bold$Mage DNS$Normal Name Servers Already Set up.\n"
  fi 
}

function force_tcp() {
  if [[ $FORCE_TCP = "on" ]]; then
    printf "$Blue2[+]$Normal Setting$Bold$Yellow2 DNS$Normal to force using tcp\n"
    printf "$Mage2[?]$Normal This used to connect to dns servers and route everything via$Bold$Yellow2 Tor$Normal\n"
    printf "$Yellow2[!]$Normal$Bold$Blue2 NOTICE:$Normal This procedure can increase latency\n$Yellow2[!]$Normal Also can be a bit slow depending on your network speed\n"
    sed -i "s/force_tcp = false/force_tcp = true/g" $DNSCRYPT_FILE
    proxy=$(grep proxy $DNSCRYPT_FILE|head -1)
    sed -i "s,${proxy},proxy = \"socks5://127\.0\.0\.1:9050\",g" $DNSCRYPT_FILE
    printf "$Green2[-]$Normal Restarting DNSCrypt.\n"
    systemctl restart $DNS_SERVICE
  elif [[ $FORCE_TCP = "off" ]]; then
    printf "$Blue2[-]$Normal Turning Off Force Tcp on$Bold$Yellow2 DNS$Normal\n"
    printf "$Blue2[-]$Normal Disabling Routing Everything on$Bold$Yellow2 DNS$Normal via$Bold$Yellow2 Tor$Normal\n"
    sed -i "s/force_tcp = true/force_tcp = false/g" $DNSCRYPT_FILE
    proxy=$(grep proxy $DNSCRYPT_FILE|head -1)
    sed -i "s,${proxy},#proxy = \"socks5://127\.0\.0\.1:9050\",g" $DNSCRYPT_FILE
    printf "$Green2[-]$Normal Restarting DNSCrypt.\n"
    systemctl restart $DNS_SERVICE
  else
    printf "$Green2[+]$Normal Routing$Bold$Yellow2 DNS$Normal Via$Bold$Yellow2 Tor$Normal Is Not Off/On, Continuing..\n"
  fi
}

function ufw_service() { 
  if [ -z "${UFW_SET}" ] || [ "${UFW_SET}" == "on" ]; then
    ufw_setup
  else 
    printf "$Red2[+]$Normal Not Setting up$Bold$Green2 UFW Rules (Iptables)$Normal\n"
  fi
}

function ufw_setup() { 
  status=$(ufw status)
  if [[ $status == "Status: inactive" ]]; then
    printf "$Blue2[!]$Normal$Bold$Yellow Firewall$Normal Is Inactive\n"  
    if [[ $(grep "9110 0.0.0.0/0" $UFW_USER) == "" ]]; then
      printf "$Blue2[+]$Normal Setting Up$Bold$Yellow Firewall$Normal\n"
      download_file "https://0x0.st/oUQv.rules" $UFW_USER
      if [[ $I_PORTS != "" ]]; then
        ports=$(echo $I_PORTS | tr ',' '\n')
        for port in $ports; do
          printf "$Mage[+]$Normal Adding Selected Port:$Bold$Green %s$Normal To Firewall rules\n" "${port}"
          if [[ $port != "9110" ]]; then
            sed -i "/### tuple ###/a\-A ufw-user-input -p udp --dport ${port} -j ACCEPT" $UFW_USER
            sed -i "/### tuple ###/a\-A ufw-user-input -p tcp --dport ${port} -j ACCEPT" $UFW_USER
          fi
        done
        if [[ $(echo $ports | grep "9110") == "" ]];then sed -i -e "/-A ufw-user-input -p udp --dport 9110 -j ACCEPT/d" -e "/-A ufw-user-input -p tcp --dport 9110 -j ACCEPT/d" $UFW_USER; fi
      else
        printf "$Blue2[+]$Normal Continuing With Default Allowed Port:$Bold$Yellow2 9110$Normal\n"
      fi
      printf "$Blue2[+]$Normal Starting$Bold$Yellow Firewall$Normal\n"
      ufw enable >/dev/null
      ufw_setup
    else
      printf "$Blue2[+]$Normal$Bold$Yellow Firewall$Normal Is Already Configured\n"
      printf "$Blue2[+]$Normal Starting$Bold$Yellow Firewall$Normal\n"
      ufw enable >/dev/null
      ufw_setup
    fi
  else
    printf "$Mage2[+]$Normal$Bold$Yellow Firewall$Normal Is Active\n"  
  fi
}


function mac_change() {
  readarray -t interfaces < <(ip l | awk -F ":" '/^[0-9]+:/{dev=$2 ; if ( dev !~ /^ lo$/) {print $2}}')
  if [[ $MAC_CHANGE == "on" ]]; then
    printf "$Blue2[+]$Normal Changing$Bold Mac Address$Normal\n"
    for i in "${interfaces[@]// /}";do 
      perm_addr=$(macchanger -s ${i} |tail -1| awk '{print $3}')
      printf "$Yellow[-]$Normal Default Mac Address:$Italic$Bold %s$Normal Interface$Italic$Bold %s$Normal\n" "${perm_addr}" "${i}"
      ip link set $i down
      macchanger -r $i &>/dev/null
      curr_addr=$(macchanger -s ${i} |head -1| awk '{print $3}')
      printf "$Yellow[-]$Normal New Mac Address:$Italic$Bold %s$Normal Interface$Italic$Bold %s$Normal\n" "${curr_addr}" "${i}"
      ip link set $i up
    done
  else
    printf "$Blue2[+]$Normal Leaving Default$Bold Mac Address$Normal\n"
  fi
  if [[ $RESET_MAC == "on" ]]; then
    printf "$Blue2[+]$Normal Reset To Default$Bold Mac Address$Normal\n"
    for i in "${interfaces[@]// /}";do 
      curr_addr=$(macchanger -s ${i} |head -1| awk '{print $3}')
      printf "$Yellow[-]$Normal Current Mac Address:$Italic$Bold %s$Normal Interface$Italic$Bold %s$Normal\n" "${curr_addr}" "${i}"
      ip link set $i down
      macchanger -p $i &>/dev/null
      curr_addr=$(macchanger -s ${i} |head -1| awk '{print $3}')
      printf "$Yellow[-]$Normal Default Mac Address:$Italic$Bold %s$Normal Interface$Italic$Bold %s$Normal\n" "${curr_addr}" "${i}"
      ip link set $i up
    done
  else
    printf "$Blue2[+]$Normal Not Reset Been Set Leaving$Bold Mac Address$Normal\n"
  fi
}

function sysctl_harden() {
  printf "$Blue2[+]$Normal$Bold Sysctl Network$Normal Tweaks\n"
  if [ ! -e $SYSCTL_TCP ]; then
    download_file "https://0x0.st/oUVV.conf" $SYSCTL_TCP
    sysctl --system 
  else
    printf "$Green2[+]$Normal$Bold Sysctl Network$Normal Already Setup\n"
  fi
}

function timezone_c() { 
  cur_timezone=$(timedatectl show|head -1|awk -F= '{print $2}')
  filename="my_setup"
  printf "$Orange[-]$Normal$Bold TimeZone$Normal Settings.\n"
  if [[ "${ZONE_RESET}" == "on" ]]; then
    cur_timezone=$(grep "TIME=" "${filename}"|awk -F= '{print $2}')
    if [[ -n "${cur_timezone}" ]]; then
      printf "$Yellow2[+]$Normal Reseting Current Timezone to$Bold %s$Normal\n" "${cur_timezone}"
      timedatectl set-timezone $cur_timezone &>/dev/null
    fi
  else
    if [[ $cur_timezone != "UTC" ]]; then
      sed -i "s,TIME=.*$,TIME=${cur_timezone},g" $filename
      printf "$Green2[+]$Normal Backed Up Current TimeZone$Bold %s$Normal\n" "${cur_timezone}"
      printf "$Blue2[+]$Normal Changing$Bold$Yellow2 Timezone$Normal To$Mage2 UTC$Normal\n" "${cur_timezone}"
      timedatectl set-timezone UTC
    fi
  fi
}

function banner() { 
  printf "$Red2     o   o\n$Yellow      )-(\n$Green2     (O O)\n$Mage      \=/\n$Blue     .-\"-.\n$White    //\ /\\\\\ \n$Red2  _// / \ \\\\\_\n$Yellow =./ {,-.} \.=\n$Green2     || ||\n$Mage     || || $Normal$Italic$Bold Good Luck Conquering The World.\n$Normal$Blue2   __|| ||__\n$White2  \`---\" \"---'$Normal\n"
}

function started() { 
  banner
  kill_all
  warning 
  printf "$Blue2[x]$Normal Reading Config, Doing Checks\n"
  if [ -f my_setup ]; then source my_setup; fi
  if [[ $SS_ON == "on" ]]; then
    FORCE_TCP="on"
    TOR_START="on"
    MAC_CHANGE="on"
    RESET_MAC="off"
    SYSCTL_NET="on"
    UFW_SET="on"
  elif [[ $SS_ON == "off" ]];then
    FORCE_TCP="off"
    TOR_START="off"
    MAC_CHANGE="off"
    RESET_MAC="on"
    SYSCTL_NET="off"
    UFW_SET="off"
    ZONE_RESET="on"
  elif [[ $FORCE_TCP == "on" && $START_TOR == "off" || -z $START_TOR ]]; then
    START_TOR="on"
  fi
  main
}

function kill_all() { 
  if [[ -n $END_ME ]]; then
    wipe
    printf "$Blue2[x]$Normal Shutting down\n"
    shutdown -P now
  fi
}

function warning() { 
  printf "$Green2[+]$Red2$Bold WARNING$Normal This is not a bulletproof anonymization tool\n"
}


function main() { 
  check_root
  if [[ -n $BRID ]]; then change_bridges; fi
  if [[ -n $WIPE ]]; then wipe;fi
  if [[ -n $END_ME ]]; then kill_all;fi
  check_live
  compatibility
  check_require
  mac_change
  timezone_c
  sysctl_harden
  dns_service
  tor_service
  force_tcp
  ufw_service 
}

started
