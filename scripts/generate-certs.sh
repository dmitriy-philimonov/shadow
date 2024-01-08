#!/bin/bash

echo "Generate custom CA"
openssl req -x509 -new -nodes -newkey rsa:4096 \
    -keyout ca.key -out ca.crt -days 1826 \
    -subj '/CN=Company CA/C=RU/ST=Moscow/O=CentralCompany'

echo "Generate server key/csr"
openssl req -new -nodes -newkey rsa:4096 \
    -keyout server.key -out server.csr \
    -subj '/CN=Company service/C=RU/ST=Moscow/O=CentralCompany'

echo "Create server cert signed by CA"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt \
    -days 730 -sha256

echo "Generate client key/csr"
openssl req -new -nodes -newkey rsa:4096 \
    -keyout client.key -out client.csr \
    -subj '/CN=Client model 1/C=RU/ST=Moscow/O=ClientCompany'

echo "Create client cert signed by CA"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt \
    -days 730 -sha256