#!/bin/bash

if [ `id -u` -ne 0 ]
then
  echo "Need root, try with sudo"
  exit 0
fi

# Show "Done."
function say_done() {
    echo " "
    echo -e "Done."
    yes "" | say_continue
}


# Ask to Continue
function say_continue() {
    echo -n " To EXIT Press x Key, Press ENTER to Continue"
    read acc
    if [ "$acc" == "x" ]; then
        exit
    fi
    echo " "
}

    echo -n " Enter your username: "; read NAME
    say_done
    
    echo -n " Enter your password: "; read PASS   
    say_done
    
    echo -n " Enter your new ssh port: "; read NEW_SSH_PORT
    say_done

# Autodetect public IP address

IP_INT="$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)"

localip=192.168.2.1
remoteip=192.168.2.10
network_interface=$(ip -o -4 route show to default | awk '{print $5}')

apt-get update
apt -y install sudo
apt -y install net-tools


apt-get -y install pptpd || {
  echo "Could not install pptpd"
  exit 1
}

echo 1 > /sys/proc/net/ipv4/ip_forward

sed -i -e 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

sysctl -p


if [ $(lsb_release -cs) = "stretch" ]; then
 

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
else 
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service
 fi

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
iptables -I INPUT -p tcp --dport $NEW_SSH_PORT -j ACCEPT
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

#rclocal has exit 0 at the end of the file.
sed -i "/^exit.*/d" /etc/rc.local


cat >> /etc/rc.local << END
/usr/sbin/iptable-set.sh || exit 1
END


echo " " | sudo tee -a /etc/rc.local
echo "exit 0" | sudo tee -a /etc/rc.local

sh /etc/rc.local


cat >/etc/ppp/chap-secrets <<END
# Secrets for authentication using CHAP
# client server secret IP addresses
$NAME pptpd $PASS *
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

#enable autostart pptpd service
service pptpd restart
sudo systemctl enable pptpd

#check if pptpd listen port
netstat -alpn | grep :1723
netstat -alon | grep :1723
sleep 5

#fix error dirmgr needed
apt -y install dirmngr

#Fix the Tor packages cannot be updated due to the gpg key is changed.
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
#debug ip-down script
sudo echo "touch /root/ip-down-script-successful" | sudo tee -a /etc/ppp/ip-down


sudo sed -i "/^iptables/d" /etc/ppp/ip-up
sudo echo "iptables -t nat -A PREROUTING -i \$PPP_IFACE -p udp --dport 53 -j REDIRECT --to-ports 5353" | sudo tee -a /etc/ppp/ip-up
sudo echo "iptables -t nat -A PREROUTING -i \$PPP_IFACE -p udp --dport 5353 -j REDIRECT --to-ports 5353" | sudo tee -a /etc/ppp/ip-up
sudo echo "iptables -t nat -A PREROUTING -i \$PPP_IFACE -p tcp --syn -j REDIRECT --to-ports 9040" | sudo tee -a /etc/ppp/ip-up
#restart tor service
sudo echo "sudo service tor restart" | sudo tee -a /etc/ppp/ip-up
#debug ip-up script
sudo echo "touch /root/ip-up-script-successful" | sudo tee -a /etc/ppp/ip-up


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

#create login pass file in root folder
cat > /root/pptp.txt << EOL
##################################################################################################################
##################################################################################################################
##################################################################################################################
Filename: /root/pptp.txt

Your server is: $IP_INT
Your auth login is: $NAME
Your auth password is: $PASS
Your new ssh port is: NEW_SSH_PORT

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

Port $NEW_SSH_PORT
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
