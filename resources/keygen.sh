#!/bin/bash
for len in 512 1024 2048 3072
do
  openssl genpkey -genparam -algorithm DSA -out dsap${len}.pem -pkeyopt dsa_paramgen_bits:${len}
  openssl genpkey -paramfile dsap${len}.pem -out dsa${len}_key.pem
  openssl req -key dsa${len}_key.pem -new -x509 -days 2000 -out dsa${len}_cert.pem -subj "/CN=tls-attacker.com"
done
for len in 512 1024 2048 4096
do
  openssl genpkey -algorithm RSA -out rsa${len}_key.pem -pkeyopt rsa_keygen_bits:${len} 
  openssl req -key rsa${len}_key.pem -new -x509 -days 2000 -out rsa${len}_cert.pem -subj "/CN=tls-attacker.com"
done
for named_curve in secp160k1 secp160r1 secp160r2 secp192k1 secp224k1 secp224r1 secp256k1 secp384r1 secp521r1 sect163k1 sect163r1 sect163r2 sect193r1 sect193r2 sect233k1 sect233r1 sect239k1 sect283k1 sect283r1 sect409k1 sect409r1 sect571k1 sect571r1
do
  openssl ecparam -name ${named_curve} -genkey -out ec_${named_curve}_key.pem
  openssl req -key ec_${named_curve}_key.pem -new -x509 -days 2000 -out ec_${named_curve}_cert.pem -subj "/CN=tls-attacker.com"
done


openssl req -x509 -new -nodes -extensions v3_ca -key rsa2048_key.pem -days 2000 -out rsa_ca.pem -sha256 -subj "/CN=TLS-Attacker CA"
openssl req -x509 -new -nodes -extensions v3_ca -key dsa1024_key.pem -days 2000 -out dsa_ca.pem -sha256 -subj "/CN=TLS-Attacker CA"

openssl dhparam -out dhparam.pem 1024
openssl genpkey -paramfile dhparam.pem -out dhkey.pem
openssl pkey -in dhkey.pem -pubout -out dhpubkey.pem
openssl req -new -key rsa2048_key.pem -out rsa.csr -subj "/CN=tls-attacker.com"
openssl x509 -req -in rsa.csr -CAkey rsa2048_key.pem -CA rsa_ca.pem -force_pubkey dhpubkey.pem -outrsa_dhcert.pem -CAcreateserial
openssl req -new -key dsa1024_key.pem -out dsa.csr -subj "/CN=tls-attacker.com"
openssl x509 -req -in dsa.csr -CAkey dsa1024_key.pem -CA dsa_ca.pem -force_pubkey dhpubkey.pem -out 
dsa_dhcert.pem -CAcreateserial
for named_curve in secp160k1 secp160r1 secp160r2 secp192k1 secp224k1 secp224r1 secp256k1 secp384r1 secp521r1 sect163k1 sect163r1 sect163r2 sect193r1 sect193r2 sect233k1 sect233r1 sect239k1 sect283k1 sect283r1 sect409k1 sect409r1 sect571k1 sect571r1
do
    openssl ecparam -out ec_param_${named_curve}.pem -name ${named_curve}
	openssl genpkey -paramfile ec_param_${named_curve}.pem -out ec_rsa_private_key_${named_curve}.pem
    openssl pkey -in ec_rsa_private_key_${named_curve}.pem -pubout -out ec_rsa_public_key_${named_curve}.pem
	openssl x509 -req -in rsa.csr -CAkey rsa2048_key.pem -CA rsa_ca.pem -force_pubkey ec_rsa_public_key_${named_curve}.pem -out ec_rsa_cert_${named_curve}.pem -CAcreateserial
done
