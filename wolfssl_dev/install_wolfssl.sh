#!/bin/bash

# Installing missing packages for Raspberry Pi:
sudo apt-get update
sudo apt-get install -y autoconf automake libtool coreutils bsdmainutils

git clone https://github.com/wolfSSL/wolfssl.git
#git clone https://github.com/julek-wolfssl/wolfssl.git
cd wolfssl
#git checkout dtls13-frag-ch2
./autogen.sh

mkdir build
cd build


../configure CFLAGS="-DHAVE_SECRET_CALLBACK" \
    --enable-opensslall \
    --enable-opensslextra \
    --enable-static \
    --enable-psk \
    --enable-alpn \
    --enable-aesccm \
    --enable-aesgcm \
    --enable-dtls-mtu \
    --enable-context-extra-user-data=yes \
    --enable-dtls \
    --enable-dtls13 \
    --enable-tls13 \
    --enable-dtls-frag-ch \
    --enable-secure-renegotiation \
    --enable-debug \
    --with-liboqs

make all
sudo make install