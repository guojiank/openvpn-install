#!/usr/bin/env bash

# useage:
#   bash openvpn-install.sh
# environment:
#   -- EASY_RSA_SKIP
#       set true skip install easyrsa
#   -- OPEN_VPN_SKIP
#       set true to skip install openvpn

set -e

LOCAL_IP=
PUBLIC_IP=
PORT=
PROTOCOL=
SUB_NET=

EASY_RSA_URL="https://github.com/leekcoder/openvpn-install/raw/main/lib/EasyRSA-3.1.0.tgz"
EASY_RSA_PATH=/etc/openvpn/easy-rsa

OPEN_VPN_URL="https://github.com/leekcoder/openvpn-install/raw/main/lib/openvpn-2.5.7.tar.gz"

fatal() {
    echo '[fatal] ' "$*" >&2
    exit 1
}

verify_os() {
    if readlink /proc/$$/exe | grep -q 'dash'; then
        fatal 'This installer needs to be run with "bash", not "sh".'
    fi
    if ! grep -iq ubuntu /etc/os-release &>/dev/null; then
        fatal 'OS must be ubuntu'
    fi
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

new_client() {
    client=$1
    {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
        echo "</key>"
        echo "<tls-crypt>"
        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
        echo "</tls-crypt>"
    } >~/"$client".ovpn
}

IP_REG="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"

#----------openvpn settings-----------
{
    verify_os
    if [ "$(command -v openvpn)" ]; then
        echo 'openvpn has install'
    else
        echo 'openvpn not install'

        until [[ $PUBLIC_IP =~ $IP_REG ]]; do
            read -r -p 'public ip address: ' PUBLIC_IP
        done

        until [[ $LOCAL_IP =~ $IP_REG ]]; do
            read -r -p 'local ip address': LOCAL_IP
        done

        until [[ $SUB_NET =~ $IP_REG ]]; do
            read -r -p 'sub network address: ' SUB_NET
        done

        until [[ $PROTOCOL =~ (tcp)|(udp) ]]; do
            read -r -p 'protocol [tcp/udp]: ' PROTOCOL
        done

        read -r -p 'port, default 1194: ' PORT
    fi
}
