#!/bin/bash

if [ $UID -ne 0 ];
	then	echo  "Superuser privileges are required to run this script."
			echo  "e.g. \"sudo $0\""
			exit 1
fi

generate_CA () {
	echo  -e "cn = \"$CN\"
organization = \"$OG\"
serial = 1
expiration_days = $ED
ca
signing_key
cert_signing_key
crl_signing_key" >> ca.tmpl
	certtool --generate-privkey --outfile ca-key.pem
	certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem
	cp ca-cert.pem /etc/ssl/certs/ca-cert.pem
}

generate_Server () {
	echo  -e "cn = \"$HOSTNAME\"
organization = \"OG\"
serial = 2
expiration_days = $ED
encryption_key
signing_key
tls_www_server" >> server.tmpl
	certtool --generate-privkey --outfile server-key.pem
	certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ../CA/ca-cert.pem --load-ca-privkey ../CA/ca-key.pem --template server.tmpl --outfile server-cert.pem
	cp server-cert.pem /etc/ssl/certs/server-cert.pem
	cp server-key.pem /etc/ssl/private/server-key.pem
}

generate_User () {
	echo  -e "cn = \"$USERNAME\"
unit = \"$OG\"
expiration_days = $ED
signing_key
tls_www_client" >> user.tmpl
	certtool --generate-privkey --outfile user-key.pem
	certtool --generate-certificate --load-privkey user-key.pem --load-ca-certificate ../CA/ca-cert.pem --load-ca-privkey ../CA/ca-key.pem --template user.tmpl --outfile user-cert.pem
	openssl pkcs12 -export -inkey user-key.pem -in user-cert.pem -certfile ../CA/ca-cert.pem -out ../../user.p12
}

with_Certs () {
	echo  "Please input the path of your certs"
	echo -n "CA Cert: "
	read PATH_CA_CERT
	echo -n "Server Cert: "
	read PATH_SERVER_CERT
	echo -n "Server Key: "
	read PATH_SERVER_KEY
}

without_Certs () {
	echo  "Now we are going to garther some essential information for generating certs."
	echo -n "Common Name: "
	read CN
	echo -n "Organization: "
	read OG
	echo -n "Expiration Day: "
	read ED
	mkdir Certs
	cd Certs
	mkdir CA
	cd CA
	generate_CA
	cd ../
	mkdir Server
	cd Server
	generate_Server
	cd ../
	PATH_CA_CERT='/etc/ssl/certs/ca-cert.pem'
	PATH_SERVER_CERT='/etc/ssl/certs/server-cert.pem'
	PATH_SERVER_KEY='/etc/ssl/private/server-key.pem'
}



mode_Password () {
	echo -n "Username: "
	read USERNAME
	ocpasswd -c /etc/ocserv/ocpasswd $USERNAME
}

mode_Certification () {
	echo -n "Username: "
	read USERNAME
	mkdir User
	cd User
	generate_User
	cd ../
}


gateway () {
	iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	sysctl -w net.ipv4.ip_forward=1
	iptables -I INPUT -p tcp --dport $TCP -j ACCEPT
	iptables -I OUTPUT -p tcp --dport $TCP -j ACCEPT
	iptables -I INPUT -p udp --dport $UDP -j ACCEPT
	iptables -I OUTPUT -p udp --dport $UDP -j ACCEPT
}

echo  "##################################################################"
echo  "##########################Ocserv Config###########################"
echo  "##################################################################"
echo  "     This script will help you to build Ocserv on your Server.    "
echo  ""
echo  ""
echo  ""
echo  ""

#Install Essentials
apt-get update
apt-get install build-essential libwrap0-dev libpam0g-dev libdbus-1-dev libreadline-dev libnl-route-3-dev libpcl1-dev libopts25-dev autogen libgnutls28-dev libseccomp-dev gnutls-bin automake openssl supervisor
#Download and install Ocserv
mkdir Ocserv
cd Ocserv
mkdir tmp
cd tmp
wget ftp://ftp.infradead.org/pub/ocserv/ocserv-0.10.2.tar.xz
tar -xf ocserv-0.10.2.tar.xz
cd ocserv-0.10.2
./configure
make
make install
cd ../
cd ../

mkdir /etc/ocserv

echo -n "Your Hostname: "
read HOSTNAME
echo -n "Do you have certs (CA & Server) for Ocserv? [Y/N]: "
read CERTS

case $CERTS in
	Y) with_Certs
	;;
	N) without_Certs
	;;
esac

echo  "The portal you want to use in ocserv."
echo -n "TCP: "
read TCP
echo -n "UDP: "
read UDP

echo -n "Which authentication way do you prefer? [Password/Certification]: "
read Auth


case $Auth in
	Password)	mode_Password
				CONFIG='plain[/etc/ocserv/ocpasswd]'
				USEROID='#cert-user-oid = 2.5.4.3'
	;;
	Certification)	mode_Certification
					CONFIG='certificate'
					USEROID='cert-user-oid = 2.5.4.3'
	;;
esac

echo -n -e "# User authentication method. Could be set multiple times and in 
# that case all should succeed. To enable multiple methods use
# multiple auth directives. Available options: certificate, certificate[optional],
# plain, pam. 
#auth = \"certificate\"
#auth = \"plain[./sample.passwd]\"
#auth = \"pam\"

# This indicates that a user may present a certificate. When that option
# is set, individual users or user groups can be forced to present a valid
# certificate by using \"require-cert=true\".
auth = \"$CONFIG\"

# The gid-min option is used by auto-select-group option, in order to
# select the minimum group ID.
#auth = \"pam[gid-min=1000]\"

# The plain option requires specifying a password file which contains
# entries of the following format.
# \"username:groupname:encoded-password\"
# One entry must be listed per line, and 'ocpasswd' can be used
# to generate password entries.
#auth = \"plain[passwd=/etc/ocserv/ocpasswd]\"

# Whether to enable seccomp worker isolation. That restricts the number of 
# system calls allowed to a worker process, in order to reduce damage from a
# bug in the worker process. It is available on Linux systems at a performance cost.
#use-seccomp = true

# Whether to enable the authentication method's session control (i.e., PAM).
# That requires more resources on the server, and makes cookies one-time-use;
# thus don't enable unless you need it.
#session-control = true

# A banner to be displayed on clients
#banner = \"Welcome\"

# Limit the number of clients. Unset or set to zero for unlimited.
#max-clients = 1024
max-clients = 20

# Limit the number of client connections to one every X milliseconds 
# (X is the provided value). Set to zero for no limit.
#rate-limit-ms = 100

# Limit the number of identical clients (i.e., users connecting 
# multiple times). Unset or set to zero for unlimited.
max-same-clients = 5

# Use listen-host to limit to specific IPs or to the IPs of a provided 
# hostname.
#listen-host = [IP|HOSTNAME]

# When the server has a dynamic DNS address (that may change),
# should set that to true to ask the client to resolve again on
# reconnects.
#listen-host-is-dyndns = true

# TCP and UDP port number
tcp-port = $TCP
udp-port = $UDP

# Accept connections using a socket file. The connections are
# forwarded without SSL/TLS.
#listen-clear-file = /var/run/ocserv-conn.socket

# Keepalive in seconds
keepalive = 3600

# Dead peer detection in seconds.
dpd = 90

# Dead peer detection for mobile clients. The needs to
# be much higher to prevent such clients being awaken too 
# often by the DPD messages, and save battery.
# (clients that send the X-AnyConnect-Identifier-DeviceType)
mobile-dpd = 1800

# MTU discovery (DPD must be enabled)
try-mtu-discovery = true

# The key and the certificates of the server
# The key may be a file, or any URL supported by GnuTLS (e.g., 
# tpmkey:uuid=xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx;storage=user
# or pkcs11:object=my-vpn-key;object-type=private)
#
# There may be multiple certificate and key pairs and each key
# should correspond to the preceding certificate.
server-cert = $PATH_SERVER_CERT
server-key = $PATH_SERVER_KEY

# Diffie-Hellman parameters. Only needed if you require support
# for the DHE ciphersuites (by default this server supports ECDHE).
# Can be generated using:
# certtool --generate-dh-params --outfile /path/to/dh.pem
#dh-params = /path/to/dh.pem

# If you have a certificate from a CA that provides an OCSP
# service you may provide a fresh OCSP status response within
# the TLS handshake. That will prevent the client from connecting
# independently on the OCSP server.
# You can update this response periodically using:
# ocsptool --ask --load-cert=your_cert --load-issuer=your_ca --outfile response
# Make sure that you replace the following file in an atomic way.
#ocsp-response = /path/to/ocsp.der

# In case PKCS #11 or TPM keys are used the PINs should be available
# in files. The srk-pin-file is applicable to TPM keys only, and is the 
# storage root key.
#pin-file = /path/to/pin.txt
#srk-pin-file = /path/to/srkpin.txt

# The Certificate Authority that will be used to verify
# client certificates (public keys) if certificate authentication
# is set.
ca-cert = $PATH_CA_CERT

# The object identifier that will be used to read the user ID in the client 
# certificate. The object identifier should be part of the certificate's DN
# Useful OIDs are: 
#  CN = 2.5.4.3, UID = 0.9.2342.19200300.100.1.1
$USEROID

# The object identifier that will be used to read the user group in the 
# client  certificate. The object identifier should be part of the certificate's
# DN. Useful OIDs are: 
#  OU (organizational unit) = 2.5.4.11 
#cert-group-oid = 2.5.4.11

# The revocation list of the certificates issued by the 'ca-cert' above.
#crl = /root/Certs/crl.pem

# GnuTLS priority string
tls-priorities = \"NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-ARCFOUR-128\"

# To enforce perfect forward secrecy (PFS) on the main channel.
#tls-priorities = \"NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-SSL3.0:-ARCFOUR-128\"

# The time (in seconds) that a client is allowed to stay connected prior
# to authentication
auth-timeout = 120

# The time (in seconds) that a client is allowed to stay idle (no traffic)
# before being disconnected. Unset to disable.
idle-timeout = 1200

# The time (in seconds) that a mobile client is allowed to stay idle (no
# traffic) before being disconnected. Unset to disable.
mobile-idle-timeout = 2400

# The time (in seconds) that a client is not allowed to reconnect after 
# a failed authentication attempt.
#min-reauth-time = 2

# Cookie timeout (in seconds)
# Once a client is authenticated he's provided a cookie with
# which he can reconnect. That cookie will be invalided if not
# used within this timeout value. On a user disconnection, that
# cookie will also be active for this time amount prior to be
# invalid. That should allow a reasonable amount of time for roaming
# between different networks.
cookie-timeout = 300

# Whether roaming is allowed, i.e., if true a cookie is
# restricted to a single IP address and cannot be re-used
# from a different IP.
deny-roaming = false

# ReKey time (in seconds)
# ocserv will ask the client to refresh keys periodically once
# this amount of seconds is elapsed. Set to zero to disable.
rekey-time = 0

# ReKey method
# Valid options: ssl, new-tunnel
#  ssl: Will perform an efficient rehandshake on the channel allowing
#       a seamless connection during rekey.
#  new-tunnel: Will instruct the client to discard and re-establish the channel.
#       Use this option only if the connecting clients have issues with the ssl
#       option.
rekey-method = ssl

# Script to call when a client connects and obtains an IP
# Parameters are passed on the environment.
# REASON, USERNAME, GROUPNAME, HOSTNAME (the hostname selected by client), 
# DEVICE, IP_REAL (the real IP of the client), IP_LOCAL (the local IP
# in the P-t-P connection), IP_REMOTE (the VPN IP of the client),
# ID (a unique numeric ID); REASON may be \"connect\" or \"disconnect\".
#connect-script = /scripts/ocserv-script
#disconnect-script = /scripts/ocserv-script

# UTMP
use-utmp = true

# Whether to enable support for the occtl tool (i.e., either through D-BUS,
# or via a unix socket).
use-occtl = true

# socket file used for IPC with occtl. You only need to set that,
# if you use more than a single servers.
#occtl-socket-file = /var/run/occtl.socket


# PID file. It can be overriden in the command line.
pid-file = /var/run/ocserv.pid

# The default server directory. Does not require any devices present.
#chroot-dir = /path/to/chroot

# socket file used for IPC, will be appended with .PID
# It must be accessible within the chroot environment (if any)
socket-file = /var/run/ocserv-socket

# The user the worker processes will be run as. It should be
# unique (no other services run as this user).
run-as-user = nobody
run-as-group = daemon

# Set the protocol-defined priority (SO_PRIORITY) for packets to
# be sent. That is a number from 0 to 6 with 0 being the lowest
# priority. Alternatively this can be used to set the IP Type-
# Of-Service, by setting it to a hexadecimal number (e.g., 0x20).
# This can be set per user/group or globally.
#net-priority = 3

# Set the VPN worker process into a specific cgroup. This is Linux
# specific and can be set per user/group or globally.
#cgroup = \"cpuset,cpu:test\"

#
# Network settings
#

# The name of the tun device
device = vpns

# Whether the generated IPs will be predictable, i.e., IP stays the
# same for the same user when possible.
predictable-ips = true

# The default domain to be advertised
default-domain = $HOSTNAME

# The pool of addresses that leases will be given from.
ipv4-network = 192.168.58.0
ipv4-netmask = 255.255.255.0

# The advertized DNS server. Use multiple lines for
# multiple servers.
# dns = fc00::4be0
dns = 208.67.222.222
dns = 208.67.220.220

# The NBNS server (if any)
#nbns = 192.168.1.3

# The IPv6 subnet that leases will be given from.
#ipv6-network = fc00::
#ipv6-prefix = 16

# The domains over which the provided DNS should be used. Use
# multiple lines for multiple domains.
#split-dns = example.com

# Prior to leasing any IP from the pool ping it to verify that
# it is not in use by another (unrelated to this server) host.
ping-leases = false

# Unset to assign the default MTU of the device
# mtu = 

# Unset to enable bandwidth restrictions (in bytes/sec). The
# setting here is global, but can also be set per user or per group.
#rx-data-per-sec = 40000
#tx-data-per-sec = 40000

# The number of packets (of MTU size) that are available in
# the output buffer. The default is low to improve latency.
# Setting it higher will improve throughput.
#output-buffer = 10

# Routes to be forwarded to the client. If you need the
# client to forward routes to the server, you may use the 
# config-per-user/group or even connect and disconnect scripts.
#
# To set the server as the default gateway for the client just
# comment out all routes from the server.
route = 0.0.0.0/128.0.0.0
route = 128.0.0.0/128.0.0.0
#route = fef4:db8:1000:1001::/64

# Configuration files that will be applied per user connection or
# per group. Each file name on these directories must match the username
# or the groupname.
# The options allowed in the configuration files are dns, nbns,
#  ipv?-network, ipv4-netmask, ipv6-prefix, rx/tx-per-sec, iroute, route,
#  net-priority and cgroup.
#
# Note that the 'iroute' option allows to add routes on the server
# based on a user or group. The syntax depends on the input accepted
# by the commands route-add-cmd and route-del-cmd (see below).

#config-per-user = /etc/ocserv/config-per-user/
#config-per-group = /etc/ocserv/config-per-group/

# When config-per-xxx is specified and there is no group or user that
# matches, then utilize the following configuration.

#default-user-config = /etc/ocserv/defaults/user.conf
#default-group-config = /etc/ocserv/defaults/group.conf

# Groups that a client is allowed to select from.
# A client may belong in multiple groups, and in certain use-cases
# it is needed to switch between them. For these cases the client can
# select prior to authentication. Add multiple entries for multiple groups.
#select-group = group1
#select-group = group2[My group 2]
#select-group = tost[The tost group]

# The name of the group that if selected it would allow to use
# the assigned by default group.
#default-select-group = DEFAULT

# Instead of specifying manually all the allowed groups, you may instruct
# ocserv to scan all available groups and include the full list. That
# option is only functional on plain authentication.
#auto-select-group = true

# The system command to use to setup a route. %{R} will be replaced with the
# route/mask and %{D} with the (tun) device.
#
# The following example is from linux systems. %{R} should be something
# like 192.168.2.0/24

#route-add-cmd = \"ip route add %{R} dev %{D}\"
#route-del-cmd = \"ip route delete %{R} dev %{D}\"

# This option allows to forward a proxy. The special strings '%{U}'
# and '%{G}', if present will be replaced by the username and group name.
#proxy-url = http://example.com/
#proxy-url = http://example.com/%{U}/%{G}/hello

#
# The following options are for (experimental) AnyConnect client 
# compatibility. 

# Client profile xml. A sample file exists in doc/profile.xml.
# This file must be accessible from inside the worker's chroot. 
# It is not used by the openconnect client.
#user-profile = /etc/ocserv/profile.xml

# Binary files that may be downloaded by the CISCO client. Must
# be within any chroot environment.
#binary-files = /path/to/binaries

# Unless set to false it is required for clients to present their
# certificate even if they are authenticating via a previously granted
# cookie and complete their authentication in the same TCP connection.
# Legacy CISCO clients do not do that, and thus this option should be 
# set for them.
cisco-client-compat = true

#Advanced options

# Option to allow sending arbitrary custom headers to the client after
# authentication and prior to VPN tunnel establishment.
#custom-header = \"X-My-Header: hi there\"" >> /etc/ocserv/ocserv.conf

gateway

echo -n -e "[program:ocserv]
command=ocserv -c /etc/ocserv/ocserv.conf -f -d 1
autorestart=true
user=root" >> /etc/supervisor/conf.d/ocserv.conf
supervisorctl update

echo  "Congratulations! Your ocserv have been installed on your Server."