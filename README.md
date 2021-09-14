# dane-ddns-acme-automator

A bash script to automate DANE/TLSA key deployment and rollover.

It takes over the certificate renewal tasks from certbot and only calls it to sign certificates.

## Requirements
certbot

python3-certbot-dns-rfc2136 # You can use other methods of dynamic DNS, but you will have to modify the script.

dig

nsupdate

openssl
