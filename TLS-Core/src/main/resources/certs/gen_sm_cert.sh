#!/bin/bash

# This script requires the Tongsuo project to be installed (see https://github.com/Tongsuo-Project/Tongsuo)

# This script generates a sm2 certificate for TLS-Attacker. It also generates a sm2 root CA certificate


#generating an extension file to trick openssl into generating a X509 v3 file (otherwise this should be optional)
echo -e "[ v3_ext ]\nkeyUsage = nonRepudiation, digitalSignature, keyEncipherment" > v3_ext.cnf


#creating a config file
echo -e "[ req ]\n\ndistinguished_name = req_distinguished_name\nx509_extensions = v3_req\nprompt = no\n[ req_distinguished_name ]\nCN = localhost\nC = DE\nST = NRW\nL = Bochum\nO = RUB\nOU = NDS\n[ v3_req ]\nkeyUsage = nonRepudiation, digitalSignature, keyEncipherment" > config_file.cnf

#creating CA key
openssl ecparam -name sm2 -genkey -out attacker_sm2_ca_key.pem

#creating CA cert
openssl req -x509 -new -nodes -extensions v3_ca -key attacker_sm2_ca_key.pem -days 2000 -out attacker_sm2_ca.pem -sm3 -subj "/CN=TLS-Attacker CA"

#creating keys
openssl req -new -key attacker_sm2_ca_key.pem -out sm2.csr -config config_file.cnf
openssl ecparam -out ec_param_sm2.pem -name sm2
#private key
openssl genpkey -paramfile ec_param_sm2.pem -out ec_sm2p256v1_key.pem
#public key
openssl pkey -in ec_sm2p256v1_key.pem -pubout -out ec_sm2p256v1_public_key_sm2.pem

#creating cert
openssl x509 -req -in sm2.csr -CAkey attacker_sm2_ca_key.pem -CA attacker_sm2_ca.pem -force_pubkey ec_sm2p256v1_public_key_sm2.pem -out ec_sm2p256v1_sm2_cert.pem -CAcreateserial -days 2000 -extfile v3_ext.cnf -extensions v3_ext

#cleanup
rm v3_ext.cnf
rm config_file.cnf
rm sm2.csr
rm ec_param_sm2.pem
rm ec_sm2p256v1_public_key_sm2.pem
