#!/bin/bash

if [ $UID -ne 0 ]; 
then    echo "Superuser privileges are required to run this script."
    	echo "e.g. \"sudo $0\""
    	exit 1
fi

echo "##################################################################"
echo "########################Shadowsocks Config########################"
echo "##################################################################"
echo "  This script will help you to build Shadowsocks on your Server.  "

echo -n "Which Prot do you want to use for Shadowsocks?"
read SERVER_PORT

#Install Essentials and Supervisor
apt-get update
apt-get upgrade
apt-get install python-pip python-m2crypto supervisor pwgen

#Install Shadowsocks by pip(python)
pip install shadowsocks
cd ./Config
mkdir /etc/shadowsocks
cp shadowsocks.conf /etc/supervisor/conf.d

PASSWORD=`pwgen -B 16 1`
echo -e "{
	\"server\":\"0.0.0.0\",
	\"server_port\":$SERVER_PORT,
	\"local_address\":\"127.0.0.1\",
	\"local_port\":1080,
	\"password\":\"$PASSWORD\",
	\"timeout\":300,
	\"method\":\"aes-256-cfb\",
	\"fast_open\": false,
	\"workers\": 1
}" >> /etc/shadowsocks/shadowsocks.json

echo "[program:shadowsocks]
command=ssserver -c /etc/shadowsocks/shadowsocks.json
autorestart=true
user=nobody" >> /etc/supervisor/conf.d/shadowsocks.conf

echo "ulimit -n 51200" >> /etc/default/supervisor

supervisorctl reload

echo "Shadowsocks has been installed on your server."
echo "The Config is following."
echo "You can change it in /etc/shadowsocks/shadowsocks.json"
echo "Port: $SERVER_PORT"
echo "Password: $PASSWORD"
echo "Method: aes-256-cfb" 