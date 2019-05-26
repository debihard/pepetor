#!/bin/sh


if [ `id -u` -ne 0 ]
then
  echo "Need root, try with sudo"
  exit 0
fi

# Autodetect public IP address

IP_INT="$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)"

localip=192.168.2.1
remoteip=192.168.2.10
network_interface=$(ip -o -4 route show to default | awk '{print $5}')

apt-get update
apt -y install sudo
apt -y install net-tools
apt -y install gpw


apt-get -y install pptpd || {
  echo "Could not install pptpd"
  exit 1
}

echo 1 > /sys/proc/net/ipv4/ip_forward

sed -i -e 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf


# IPv6 disabled
#net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.default.disable_ipv6 = 1
#net.ipv6.conf.lo.disable_ipv6 = 1
sysctl -p



#create and enable debian 9 rc.local service
touch /etc/rc.local


cat > /etc/rc.local << EOF
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.
 
exit 0
EOF

cat > /etc/systemd/system/rc-local.service << END

[Unit]
 Description=/etc/rc.local Compatibility
 ConditionPathExists=/etc/rc.local
 
[Service]
 Type=forking
 ExecStart=/etc/rc.local start
 TimeoutSec=0
 StandardOutput=tty
 RemainAfterExit=yes
 SysVStartPriority=99
 
[Install]
 WantedBy=multi-user.target

END

chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service


touch /usr/sbin/iptable-set.sh
cat > /usr/sbin/iptable-set.sh << END
#!/bin/sh

iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o $network_interface -j MASQUERADE
iptables --table nat --append POSTROUTING --out-interface ppp+ -j MASQUERADE
iptables -I INPUT -s 192.168.2.0/24 -i ppp+ -j ACCEPT
iptables --append FORWARD --in-interface $network_interface -j ACCEPT
#ssh channel
iptables -I INPUT -p tcp --dport 22 -j ACCEPT
iptables -I INPUT -p tcp --dport 50099 -j ACCEPT
#control channel
iptables -I INPUT -p tcp --dport 1723 -j ACCEPT
#gre tunnel protocol
iptables -I INPUT  --protocol 47 -j ACCEPT
#iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -d 0.0.0.0/0 -o $network_interface -j MASQUERADE
#supposedly makes the vpn work better
iptables -I FORWARD -s 192.168.2.0/24 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j TCPMSS --set-mss 1356
touch /root/rc-local-script-successful
END

chmod +x /usr/sbin/iptable-set.sh

#ubuntu has exit 0 at the end of the file.
sed -i "/^exit.*/d" /etc/rc.local


cat >> /etc/rc.local << END
/usr/sbin/iptable-set.sh || exit 1
END


echo " " | sudo tee -a /etc/rc.local
echo "exit 0" | sudo tee -a /etc/rc.local

sh /etc/rc.local



#no liI10oO chars in password


   P1=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
   P2=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
   P3=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
   PASS="$P1-$P2-$P3"
   TEMP_PASS="vpn777"

   NAME=$(gpw 1 7)


cat >/etc/ppp/chap-secrets <<END
# Secrets for authentication using CHAP
# client server secret IP addresses
$NAME pptpd $PASS *
#$NAME pptpd $TEMP_PASS *
END



cat >/etc/pptpd.conf <<END
option /etc/ppp/options.pptpd
logwtmp
localip $localip
#remoteip 192.168.2.10-100
remoteip $remoteip
END

cat >/etc/ppp/options.pptpd <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
#ms-dns 8.8.8.8
#ms-dns 8.8.4.4
ms-dns $localip
proxyarp
lock
nobsdcomp
debug
dump
idle 300
novj
novjccomp
nologfd
END

apt-get -y install wget || {
  echo "Could not install wget, required to retrieve your IP address."
  exit 1
}

#find out external ip
IP=`wget -q -O - http://api.ipify.org`

if [ "x$IP" = "x" ]
then
  echo "============================================================"
  echo "  !!!  COULD NOT DETECT SERVER EXTERNAL IP ADDRESS  !!!"
else
  echo "============================================================"
  echo "Detected your server external ip address: $IP"
fi
echo   ""
echo   "VPN username = $NAME   password = $PASS"
#echo   "VPN username = $NAME   password = $TEMP_PASS"
echo   "============================================================"
sleep 5

#enable autostart pptpd service
service pptpd restart
sudo systemctl enable pptpd

#check if pptpd listen port
netstat -alpn | grep :1723
netstat -alon | grep :1723
sleep 5

apt -y install gpw
#apt -y install pwgen
apt -y install dirmngr


#Fix the Tor packages cannot be updated due to the gpg key is changed.
#gpg --keyserver keys.gnupg.net --recv 886DDD89
#gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -

wget https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc
apt-key add A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc
rm A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc

#add Tor repo
if [ -f /etc/apt/sources.list.d/tor.list ]
then
  sudo rm /etc/apt/sources.list.d/tor.list
else
  sudo touch /etc/apt/sources.list.d/tor.list
fi
echo "deb http://deb.torproject.org/torproject.org $(lsb_release -cs) main" > /etc/apt/sources.list.d/tor.list
sudo apt update

# install Tor keyring
sudo apt -y install deb.torproject.org-keyring
sudo apt update

# install Tor
sudo apt -y install tor tor-geoipdb


sudo sed -i "/^iptables/d" /etc/ppp/ip-down
sudo echo "iptables -t nat -D PREROUTING -i \$PPP_IFACE -p udp --dport 53 -j REDIRECT --to-ports 5353" | sudo tee -a /etc/ppp/ip-down
sudo echo "iptables -t nat -D PREROUTING -i \$PPP_IFACE -p udp --dport 5353 -j REDIRECT --to-ports 5353" | sudo tee -a /etc/ppp/ip-down
sudo echo "iptables -t nat -D PREROUTING -i \$PPP_IFACE -p tcp --syn -j REDIRECT --to-ports 9040" | sudo tee -a /etc/ppp/ip-down
sudo echo "touch /root/ip-down-script-successful" | sudo tee -a /etc/ppp/ip-down


sudo sed -i "/^iptables/d" /etc/ppp/ip-up
sudo echo "iptables -t nat -A PREROUTING -i \$PPP_IFACE -p udp --dport 53 -j REDIRECT --to-ports 5353" | sudo tee -a /etc/ppp/ip-up
sudo echo "iptables -t nat -A PREROUTING -i \$PPP_IFACE -p udp --dport 5353 -j REDIRECT --to-ports 5353" | sudo tee -a /etc/ppp/ip-up
sudo echo "iptables -t nat -A PREROUTING -i \$PPP_IFACE -p tcp --syn -j REDIRECT --to-ports 9040" | sudo tee -a /etc/ppp/ip-up
sudo echo "touch /root/ip-up-script-successful" | sudo tee -a /etc/ppp/ip-up
sudo echo "sudo service tor restart" | sudo tee -a /etc/ppp/ip-up


# configure /etc/tor/torrc
# remove all settings and then re-setting them up
#sudo sed -i "/^RunAsDaemon/d" /etc/tor/torrc
sudo sed -i "/^VirtualAddrNetwork/d" /etc/tor/torrc
sudo sed -i "/^AutomapHostsOnResolve/d" /etc/tor/torrc
sudo sed -i "/^AutomapHostsSuffixes/d" /etc/tor/torrc
sudo sed -i "/^TransPort/d" /etc/tor/torrc
sudo sed -i "/^DNSPort/d" /etc/tor/torrc
sudo sed -i "/^ExcludeExitNodes/d" /etc/tor/torrc
sudo sed -i "/^ExcludeNodes/d" /etc/tor/torrc
sudo sed -i "/^FascistFirewall/d" /etc/tor/torrc
sudo sed -i "/^SafeSocks/d" /etc/tor/torrc
sudo sed -i "/^SOCKSPort/d" /etc/tor/torrc
sudo sed -i "/^OptimisticData/d" /etc/tor/torrc
sudo sed -i "/^BandwidthBurst/d" /etc/tor/torrc
sudo sed -i "/^MaxCircuitDirtiness/d" /etc/tor/torrc

#echo "RunAsDaemon 1" | sudo tee -a /etc/tor/torrc
echo "VirtualAddrNetworkIPv4 10.192.0.0/10" | sudo tee -a /etc/tor/torrc
echo "AutomapHostsOnResolve 1" | sudo tee -a /etc/tor/torrc
#echo "AutomapHostsSuffixes .exit,.onion" | sudo tee -a /etc/tor/torrc
echo "TransPort $localip:9040" | sudo tee -a /etc/tor/torrc
echo "DNSPort $localip:5353" | sudo tee -a /etc/tor/torrc
echo "ExcludeExitNodes {CN},{RO},{TW},{US},{HK},{IR},{RU},{UK}" | sudo tee -a /etc/tor/torrc
echo "ExcludeNodes {CN},{RO},{TW},{US},{HK},{IR},{RU},{UK}" | sudo tee -a /etc/tor/torrc
echo "FascistFirewall 1" | sudo tee -a /etc/tor/torrc
#echo "SafeSocks 1" | sudo tee -a /etc/tor/torrc
#echo "SOCKSPort 9050" | sudo tee -a /etc/tor/torrc
echo "OptimisticData 1" | sudo tee -a /etc/tor/torrc
echo "BandwidthBurst 2 GBytes" | sudo tee -a /etc/tor/torrc
echo "MaxCircuitDirtiness 600" | sudo tee -a /etc/tor/torrc


sudo /etc/init.d/tor restart

cat > /root/pptp.txt << EOL
##################################################################################################################
##################################################################################################################
##################################################################################################################
Filename: /root/pptp.txt

Your server is: $IP_INT
Your auth login is: $NAME
Your auth password is: $PASS

Have a nice day!!!
##################################################################################################################
##################################################################################################################
##################################################################################################################
EOL

#change to local dns
cp /etc/resolv.conf /etc/resolv.conf.bak
echo "nameserver $localip" > /etc/resolv.conf

#change standart ssh port to 50099

cat > /etc/ssh/sshd_config_new << EOF

Port 50099
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
SyslogFacility AUTH
ClientAliveCountMax 2
Compression no
LogLevel VERBOSE
MaxAuthTries 2
MaxSessions 5
LoginGraceTime 30
PermitRootLogin yes
StrictModes yes
PubkeyAuthentication yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding no
AllowTcpForwarding no
PermitUserEnvironment no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
UseDNS no
#MaxStartups 2
EOF

mv /etc/ssh/sshd_config_new /etc/ssh/sshd_config
service sshd restart

cat /root/pptp.txt


exit
