#!/bin/bash

# This script generates certificates needed in the TLS-Attacker. More precisely, it first generates a RSA, DSA, and ecdsa root CA certificate
# It then creates DiffieHellman, RSA, DSA and ecdsa leaf certificates which it signs with EACH of the three root certificates

#generate an extension file to trick openssl into generating a X509 v3 file (otherwise this should be optional)
touch v3.ext
echo 'basicConstraints=CA:FALSE' > v3.ext

#root-CA-rsa key
openssl genrsa -out attacker_rsa_ca_key.pem 2048
openssl req -x509 -new -nodes -key attacker_rsa_ca_key.pem -sha256 -days 3650 -out attacker_rsa_ca.pem -subj="/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS"

#root-CA-dsa key
openssl genpkey -genparam -algorithm DSA -out attacker_dsa_cap.pem -pkeyopt dsa_paramgen_bits:2048
openssl genpkey -paramfile attacker_dsa_cap.pem -out attacker_dsa_ca_key.pem
openssl req -key attacker_dsa_ca_key.pem -new -x509 -days 2000 -out attacker_dsa_ca.pem -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS"
rm attacker_dsa_cap.pem

#root-CA ecdsa
openssl ecparam -name secp256r1 -genkey -out attacker_ecdsa_ca_key.pem
openssl req -key attacker_ecdsa_ca_key.pem -new -x509 -days 2000 -out attacker_ecdsa_ca.pem -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS"

#gen dh keys and pems
for len in 512 1024 2048 3072
do
  openssl dhparam -out dhparam.pem ${len}
  openssl genpkey -paramfile dhparam.pem -out dh${len}_key.pem
  openssl pkey -in dh${len}_key.pem -pubout -out dh.pem
  # DH is a bit weird as we have to generate the certificate request over the root CA certificates
  openssl req -new -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=localhost" -key attacker_rsa_ca_key.pem -out rsa.csr
  openssl req -new -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=localhost" -key attacker_dsa_ca_key.pem -out dsa.csr
  openssl req -new -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=localhost" -key attacker_ecdsa_ca_key.pem -out ecdsa.csr
  openssl x509 -req -in rsa.csr -CA attacker_rsa_ca.pem -CAkey attacker_rsa_ca_key.pem -force_pubkey dh.pem -CAcreateserial -out dh${len}_rsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in dsa.csr -CA attacker_dsa_ca.pem -CAkey attacker_dsa_ca_key.pem -force_pubkey dh.pem -CAcreateserial -out dh${len}_dsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in ecdsa.csr -CA attacker_ecdsa_ca.pem -CAkey attacker_ecdsa_ca_key.pem -force_pubkey dh.pem -CAcreateserial -out dh${len}_ecdsa_cert.pem -days 1024 -extfile v3.ext
done
rm dh.pem
rm dhparam.pem
rm rsa.csr
rm dsa.csr
rm ecdsa.csr

#gen DSA keys and pems
for len in 512 1024 2048 3072
do
  #dsa parameters
  openssl genpkey -genparam -algorithm DSA -out dsap${len}.pem -pkeyopt dsa_paramgen_bits:${len}
  openssl genpkey -paramfile dsap${len}.pem -out dsa${len}_key.pem
  openssl req -new -nodes -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=localhost" -key dsa${len}_key.pem -out dsa${len}_key.csr
  #signing with CA keys
  openssl x509 -req -in dsa${len}_key.csr -CA attacker_rsa_ca.pem -CAkey attacker_rsa_ca_key.pem -CAcreateserial -out dsa${len}_rsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in dsa${len}_key.csr -CA attacker_dsa_ca.pem -CAkey attacker_dsa_ca_key.pem -CAcreateserial -out dsa${len}_dsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in dsa${len}_key.csr -CA attacker_ecdsa_ca.pem -CAkey attacker_ecdsa_ca_key.pem -CAcreateserial -out dsa${len}_ecdsa_cert.pem -days 1024 -extfile v3.ext
  rm dsa${len}_key.csr
  rm dsap${len}.pem
done

#gen RSA keys and pems
for len in 512 1024 2048 4096
do
  #rsa parameters
  openssl genpkey -algorithm RSA -out rsa${len}_key.pem -pkeyopt rsa_keygen_bits:${len} 
  openssl req -new -nodes -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=localhost" -key rsa${len}_key.pem -out rsa${len}_key.csr
  #signing with CA keys
  openssl x509 -req -in rsa${len}_key.csr -CA attacker_rsa_ca.pem -CAkey attacker_rsa_ca_key.pem -CAcreateserial -out rsa${len}_rsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in rsa${len}_key.csr -CA attacker_dsa_ca.pem -CAkey attacker_dsa_ca_key.pem -CAcreateserial -out rsa${len}_dsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in rsa${len}_key.csr -CA attacker_ecdsa_ca.pem -CAkey attacker_ecdsa_ca_key.pem -CAcreateserial -out rsa${len}_ecdsa_cert.pem -days 1024 -extfile v3.ext
  rm rsa${len}_key.csr
done

#gen ec_names_curve keys and pems
for named_curve in secp160k1 secp160r1 secp160r2 secp192k1 secp224k1 secp224r1 secp256k1 secp256r1 secp384r1 secp521r1 sect163k1 sect163r1 sect163r2 sect193r1 sect193r2 sect233k1 sect233r1 sect239k1 sect283k1 sect283r1 sect409k1 sect409r1 sect571k1 sect571r1
do
  #ec parameters
  openssl ecparam -name ${named_curve} -genkey -out ec_${named_curve}_key.pem
  openssl req -new -nodes -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=localhost" -key ec_${named_curve}_key.pem -out ec_${named_curve}_key.csr
  #signing with CA keys
  openssl x509 -req -in ec_${named_curve}_key.csr -CA attacker_rsa_ca.pem -CAkey attacker_rsa_ca_key.pem -CAcreateserial -out ec_${named_curve}_rsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in ec_${named_curve}_key.csr -CA attacker_dsa_ca.pem -CAkey attacker_dsa_ca_key.pem -CAcreateserial -out ec_${named_curve}_dsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in ec_${named_curve}_key.csr -CA attacker_ecdsa_ca.pem -CAkey attacker_ecdsa_ca_key.pem -CAcreateserial -out ec_${named_curve}_ecdsa_cert.pem -days 1024 -extfile v3.ext
  rm ec_${named_curve}_key.csr
done

# TODO: implemented GOST curves

#cleanup
rm attacker_rsa_ca.srl
rm attacker_dsa_ca.srl
rm attacker_ecdsa_ca.srl
rm v3.ext


# This part of the script requires the Tongsuo project to be installed (see https://github.com/Tongsuo-Project/Tongsuo)
# This generates a sm2 certificate for TLS-Attacker. It also generates a sm2 root CA certificate
if openssl ecparam -name sm2 >/dev/null 2>&1; then

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
fi
