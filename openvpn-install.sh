#!/usr/bin/env bash

set -e
# EASY_RSA_URL="https://github.com/leekcoder/openvpn-install/raw/main/lib/EasyRSA-3.1.0.tgz"
OPEN_VPN_URL="http://swupdate.openvpn.org/community/releases/openvpn-2.5.7.tar.gz"
EASY_RSA_PATH=/etc/openvpn/easy-rsa

export EASYRSA_CERT_EXPIRE=36500
export EASYRSA_CRL_DAYS=36500

CUR_DIR=$(pwd)

install_depency() {
    if grep -qs "ubuntu" /etc/os-release; then
        apt install -y openssl*
    fi
}

compile_install_openvpn() {
    mkdir /tmp/openvpn -p
    wget -qO- $OPEN_VPN_URL | tar zx -C /tmp/openvpn --strip-components 1
    # tar -zxf ./lib/openvpn-2.5.7.tar.gz -C /tmp/openvpn --strip-components 1
    cd /tmp/openvpn || exit 1
    ./configure
    make && make install
    rm -rf /tmp/openvpn
}

install_easy_rsa() {
    # wget -qO- $EASY_RSA_URL | tar -zx -C $EASY_RSA_PATH --strip-components 1
    cd "$CUR_DIR"
    mkdir -p $EASY_RSA_PATH
    tar -zxf ./lib/EasyRSA-3.1.0.tgz -C $EASY_RSA_PATH --strip-components 1
}

openvpn_install() {
    echo "开始安装openvpn..."
    if [ "$(command -v apt)" ]; then
        apt install -y openvpn
    fi
    if [ "$(command -v yum)" ]; then
        yum install -y openvpn
    fi
    if [ ! "$(command -v openvpn)" ]; then
        install_depency
        compile_install_openvpn
    fi
    install_easy_rsa
    echo "安装完成."
}

new_client() {

    if [ ! -f "/etc/openvpn/server/server.conf" ]; then
        echo "请先创建服务端"
        return
    fi

    clear
    read -rep '客户端名称: ' client
    read -rep '服务端协议类型[tcp/udp]: ' protocol
    read -rep '服务端公网ip: ' public_ip
    read -rep '服务端端口: ' port

    cat >/etc/openvpn/server/client-common.txt <<EOF
client
dev tun
proto $protocol
remote $public_ip $port
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
    cd $EASY_RSA_PATH
    ./easyrsa build-client-full "$client" nopass
    {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat $EASY_RSA_PATH/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' $EASY_RSA_PATH/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat $EASY_RSA_PATH/pki/private/"$client".key
        echo "</key>"
        echo "<tls-crypt>"
        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
        echo "</tls-crypt>"
    } >~/"$client".ovpn
    echo "生成客户端配置地址为: ~/$client.ovpn"
}

new_server() {
    clear
    if [ -f "/etc/openvpn/server/server.conf" ]; then
        echo "File \"/etc/openvpn/server/server.conf\" exists"
        overwrite=
        until [[ $overwrite =~ ^[yYnN]$ ]]; do
            read -rep '确定要覆盖已有配置文件吗[yYnN]: ' overwrite
        done
        if [[ $overwrite =~ ^[nN]$ ]]; then
            return
        fi
    fi
    clear
    read -rep '本地ip: ' local_ip
    read -rep '开放端口: ' port
    read -rep '协议[tcp/udp]: ' protocol
    read -rep 'vpn使用网段: ' subnet

    cd $EASY_RSA_PATH || exit 1
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa build-server-full server nopass
    ./easyrsa gen-crl
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
local $local_ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server $subnet 255.255.255.0
# push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
# user nobody
# group nobody
persist-key
persist-tun
verb 3
crl-verify crl.pem
EOF

    if [ -f "/lib/systemd/system/openvpn@.service" ]; then
        mv /lib/systemd/system/openvpn@.service /lib/systemd/system/openvpn@.service.bak
    fi
    cat >/etc/systemd/system/openvpn.service <<EOF
[Unit]
Description=OpenVPN service for %I
After=network-online.target
Wants=network-online.target
Documentation=man:openvpn(8)
Documentation=https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
Documentation=https://community.openvpn.net/openvpn/wiki/HOWTO

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn/server
ExecStart=openvpn --status /var/log/status-openvpn.log --status-version 2 --suppress-timestamps --config server.conf
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
LimitNPROC=10
DeviceAllow=/dev/null rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=true
ProtectHome=true
KillMode=process
RestartSec=5s
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now openvpn
}

#----------openvpn settings-----------
{

    if readlink /proc/$$/exe | grep -q 'dash'; then
        echo '请使用bash运行此脚本!'
        exit 1
    fi

    while true; do
        clear
        item=
        until [[ $item =~ ^[1234]$ ]]; do
            echo '1) 生成客户端配置'
            echo '2) 生成服务端配置'
            echo '3) 安装openvpn'
            echo '4) 退出'
            echo ''
            read -rep '请选择操作: ' item
        done

        case "${item}" in
        1)
            new_client
            ;;
        2)
            new_server
            ;;
        3)
            install_depency
            openvpn_install
            ;;
        4)
            exit 0
            ;;
        *)
            echo "default (none of above)"
            ;;
        esac
        read -rep '按任意键继续...'
    done

}
