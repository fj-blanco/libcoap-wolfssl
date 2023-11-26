# Building libcoap with wolfSSL

## Building wolfSSL for libcoap

If you want to enable PQ cryptography in wolfSSL, you first need to build **liboqs**. You can use the `install_liboqs_for_wolfssl.sh` script as a reference.

Then you can use `install_wolfssl.sh` to build wolfSSL with liboqs.

## Building libcoap

```bash
cd libcoap-wolfssl
make clean
autogen.sh --clean
sudo make uninstall

./autogen.sh
./configure --enable-dtls --with-wolfssl --disable-manpages --disable-doxygen --enable-tests
make
sudo make install
```

You can set signature algorithms with:

```bash
CPPFLAGS="-DCOAP_WOLFSSL_SIGALGS=\"\\\"RSA+SHA256\\\"\"" \
./configure --enable-dtls --with-wolfssl --disable-manpages --disable-doxygen --enable-tests
```

You can set groups, including PQ KEMs with:

```bash
CPPFLAGS="-DCOAP_WOLFSSL_GROUPS=\"\\\"KYBER_LEVEL3\\\"\"" \
./configure --enable-dtls --with-wolfssl --disable-manpages --disable-doxygen --enable-tests
```

## Testing wolfSSL integration with libcoap

Note: I have defined the macro `HRR_COOKIE` in the file `src/coap_wolfssl.c` to enable the HelloRetryRequest cookie.

### Testing with default groups

Generate certificates

```bash
openssl req -newkey rsa:2048 -nodes -keyout server_key.pem -x509 -days 365 -out server_cert.pem
openssl req -newkey rsa:2048 -nodes -keyout client_key.pem -x509 -days 365 -out client_cert.pem
```

Server-side

```bash
./libcoap-wolfssl/examples/coap-server -A ::1 -c ${certs_path}/server_cert.pem -j ${certs_path}/server_key.pem
```

Client-side

```bash
./libcoap-wolfssl/examples/coap-client -m get coaps://[::1]/
```

Check on port 5684.

It works in both `#define HRR_COOKIE 1` and `#define HRR_COOKIE 0` modes.

### Certificate and key in same file

Generate certificates

```bash
${OPENSSL} genpkey -algorithm RSA -out rsa_2048_root_key.pem
${OPENSSL} genpkey -algorithm RSA -out rsa_2048_entity_key.pem

# Generate the root certificate
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 512 -key rsa_2048_root_key.pem -out rsa_2048_root_cert.pem

# Generate the entity CSR.
${OPENSSL} req -new -config entity.conf -key rsa_2048_entity_key.pem -out rsa_2048_entity_req.pem

# Generate the entity X.509 certificate.
${OPENSSL} x509 -req -in rsa_2048_entity_req.pem -CA rsa_2048_root_cert.pem -CAkey rsa_2048_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 513 -out rsa_2048_entity_cert.pem

# Concatenate the entity key and certificate into a single file.
cat ./certs/rsa/rsa_2048_root_cert.pem ./certs/rsa/rsa_2048_root_key.pem > ./certs/rsa/rsa_2048_root.p12
```

where `${OPENSSL}` is the path to the OpenSSL binary with liboqs support.

Run server:

```bash
./libcoap/examples/coap-server -c ./certs/rsa/rsa_2048_root.p12 -A ::1
```

Run client:

```bash
./libcoap/examples/coap-client -m get coaps://[::1]/
```

### Testing with PQ KEMs

Build libcoap specifying the `COAP_WOLFSSL_GROUPS` macro with the desired PQ KEMs. For example, for `KYBER_LEVEL1`:

```bash
CPPFLAGS="-DCOAP_WOLFSSL_GROUPS=\"\\\"KYBER_LEVEL1\\\"\"" \
./configure --enable-dtls --with-wolfssl --disable-manpages --disable-doxygen --enable-tests
```

Server-side

```bash
./libcoap-wolfssl/examples/coap-server -A ::1 -c ${certs_path}/server_cert.pem -j ${certs_path}/server_key.pem
```

Client-side

```bash
./libcoap-wolfssl/examples/coap-client -m get coaps://[::1]/
```

I have tried `KYBER_LEVEL3` and `KYBER_LEVEL5`. I have tried all in both modes `#define HRR_COOKIE 1` and `#define HRR_COOKIE 0`. `KYBER_LEVEL3` and `KYBER_LEVEL5` doesn't work with the later, but this also happens with wolfSSL's sample server and client in isolated DTLS 1.3 handshake.

### Testing with PQ signatures

Generate certificates (see [here](https://github.com/wolfSSL/osp/tree/master/oqs)).

Then run the server

```bash
./libcoap/examples/coap-server -A ::1 -c ${certs_path}/dilithium3_root_cert.pem -j ${certs_path}/dilithium3_root_key.pem
```

and the client

```bash
./libcoap-wolfssl/examples/coap-client -m get coaps://[::1]/
```

I have tested this with `falcon_level1` and `falcon_level1` sucessfully as well.

### PSK mode

PSK Mode
Generate Pre-Shared Key:

```bash
openssl rand -hex 32 > psk.txt
```

Run Server in PSK Mode:

```bash
./libcoap/examples/coap-server -k $(cat psk.txt) -h myHint -A ::1
```

Run Client in PSK Mode:

```bash
./libcoap/examples/coap-client -m get -k $(cat psk.txt) -u myHint coaps://[::1]/
```

## Running `testdriver` tests

Build libcoap with the `--enable-tests` option and run

```bash
./libcoap/tests/testdriver
```

## Analyzing the traffic with Wireshark with PQ support

See [OQS-wireshark](https://github.com/open-quantum-safe/oqs-demos/blob/main/wireshark/USAGE.md) for more details. Perhaps you need to run

```console
xhost +si:localuser:root
```

instead of

```console
xhost +si:localuser:$USER
```

if your user is not in the **docker** group. In that case

```console
sudo docker run --net=host --privileged --env="DISPLAY" --volume="$HOME/.Xauthority:/root/.Xauthority:rw" openquantumsafe/wireshark
```