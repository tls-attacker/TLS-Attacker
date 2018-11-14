#!/bin/sh

for len in 512 1024 2048
do
  openssl genpkey -genparam -algorithm DSA -out dsap${len}.pem -pkeyopt dsa_paramgen_bits:${len}
  openssl genpkey -paramfile dsap${len}.pem -out dsa${len}key.pem
  openssl req -key dsa${len}key.pem -new -x509 -days 365 -out dsa${len}cert.pem -subj "/C=DE/ST=NRW/L=Bochum/O=<script>alert('TLS-Attacker')<\/script>/CN=tls-attacker.de"
  rm dsap${len}.pem
  cat dsa${len}key.pem dsa${len}cert.pem > dsa${len}.pem
done

for len in 512 1024 2048 4096
do
  openssl genpkey -algorithm RSA -out rsa${len}key.pem -pkeyopt rsa_keygen_bits:${len} 
  openssl req -key rsa${len}key.pem -new -x509 -days 365 -out rsa${len}cert.pem -subj "/C=DE/ST=NRW/L=Bochum/O=<script>alert('TLS-Attacker')<\/script>/CN=tls-attacker.de"
  cat rsa${len}key.pem rsa${len}cert.pem > rsa${len}.pem
done

for len in 192 256 384 521
do
  openssl genpkey -algorithm EC -out ec${len}key.pem -pkeyopt ec_paramgen_curve:P-${len} -pkeyopt ec_param_enc:named_curve
  openssl req -key ec${len}key.pem -new -x509 -days 365 -out ec${len}cert.pem -subj "/C=DE/ST=NRW/L=Bochum/O=<script>alert('TLS-Attacker')<\/script>/CN=tls-attacker.de"
  cat ec${len}key.pem ec${len}cert.pem > ec${len}.pem
done