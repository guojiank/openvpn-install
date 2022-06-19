#!/usr/bin/env bash

# useage:
#   bash openvpn-install.sh
# environment:
#   -- EASY_RSA_SKIP
#       set true skip install easyrsa
#   -- OPEN_VPN_SKIP
#       set true to skip install openvpn

set -e

OS=
LOCAL_IP=
PUBLIC_IP=
PORT=
PROTOCOL=
SUB_NET=

EASY_RSA_URL="http://localhost/EasyRSA-3.1.0.tgz"
EASY_RSA_PATH=/etc/openvpn/easy-rsa

OPEN_VPN_URL="http://localhost/openvpn-2.5.7.tar.gz"

check_run_environment() {
    if readlink /proc/$$/exe | grep -q 'dash'; then
        fatal 'This installer needs to be run with "bash", not "sh".'
    fi
}

check_os() {
    if grep -iq ubuntu /etc/os-release &>/dev/null; then
        OS='ubuntu'
        return
    fi
    [ -z $OS ] && fail 'Unknow OS!!'
}

easyrsa_install() {
    [ "$EASY_RSA_SKIP" = true ] && return
    wget -qO- $EASY_RSA_URL | tar -zx -C $EASY_RSA_PATH --strip-components 1
}

openvpn_install() {
    [ "$OPEN_VPN_SKIP" = true ] && return
    wget -qO- $OPEN_VPN_URL | tar zx -C /tmp/openvpn --strip-components 1
    cd /tmp/openvpn
    # todo
}

configure_server() {
    cd $EASY_RSA_PATH
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    EASYRSA_CERT_EXPIRE=36500 ./easyrsa build-server-full server nopass
    EASYRSA_CRL_DAYS=36500 ./easyrsa gen-crl
    mkdir -p /etc/openvpn/server
    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
    openvpn --genkey --secret /etc/openvpn/server/tc.key
    cat >/etc/openvpn/server/dh.pem <<EOF
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
EOF
    cat >/etc/openvpn/server/server.conf <<EOF
local $LOCAL_IP
port $PORT
proto $PROTOCOL
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server $SUB_NET 255.255.255.0
# push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nobody
persist-key
persist-tun
verb 3
crl-verify crl.pem
EOF
}

configure_iptables() {
    iptables_path=$(command -v iptables) || iptables
    cat >/etc/systemd/system/openvpn-iptables.servie <<EOF
[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s $SUB_NET/24 ! -d $SUB_NET/24 -j SNAT --to $LOCAL_IP
ExecStart=$iptables_path -I INPUT -p $PROTOCOL --dport $PROT -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s $SUB_NET/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s $SUB_NET/24 ! -d $SUB_NET/24 -j SNAT --to $LOCAL_IP
ExecStop=$iptables_path -D INPUT -p $PROTOCOL --dport $PROT -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $SUB_NET/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target"
EOF
    systemctl enable --now openvpn-iptables.service
}

configure_client() {
    cat >/etc/openvpn/server/client-common.txt <<EOF
client
dev tun
proto $PROTOCOL
remote $PUBLIC_IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
# ignore-unknown-option block-outside-dns
# block-outside-dns
verb 3
EOF
}

#----------openvpn settings-----------
{
    check_run_environment
    check_os
    download
}
