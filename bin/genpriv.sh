#!/bin/bash

#Generate the private and public keys
openssl ecparam -name secp256k1 -genkey -noout | openssl ec -text -noout > /tmp/Key

# Extract the public key and remove the EC prefix 0x04
PUB=`cat /tmp/Key | grep pub -A 5 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^04//'`

# Extract the private key and remove the leading zero byte
PRIV=`cat /tmp/Key | grep priv -A 3 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^00//'`

echo "{'pub':'0x$PUB','priv':'0x$PRIV'}"

rm /tmp/Key
# Generate the hash and take the address part
#cat pub | keccak-256sum -x -l | tr -d ' -' | tail -c 41 > address

