#!/bin/bash
set -Eeuo pipefail

# -- Configuration
# E-mail address for letsencrypt
readonly email="changeme"
# Domains you want to manage
readonly domains=("ecorp.com" "notsketchydomain.com")
# Subdomains you want to manage, they have to be a subdomain of partent domains already configured. Configure the subdomain as key and the parent domain as value
# This is because sub and parent domains share the same wildcard certificate
readonly -A subdomains=(["webmail.notsketchydomain.com"]=notsketchydomain.com ["ubersecret-intranet.ecorp.com"]=ecorp.com)

# Authoritative nameservers for your domains, used for sanity checking.
readonly nameservers=("ns1.ecorp.com." "ns2.ecorp.com.")
# Recursive nameservers to verify correct delegation as sanity check.
readonly externalresolvers=("dns.google." "one.one.one.one." "dns9.quad9.net.")
# Hostname or IP and portnumber of Dynamic DNS server, the shared key is stored in acme.key. This is only used by nsupdate to add TLSA records, certbot has its own configuration file (rfc2136.ini)
readonly ddnsserver="::1 5300"
# -- End of configuration

updatedglobal=0

sig_trap() {
  echo "Signal caught. Stopping now"
  trap - SIGINT SIGTERM # Disable traps to avoid endless loops
  kill -- -$$ # Kill all processes
}

fault_trap() {
  echo "Exception triggerd! Stopping">&2
  exit 1
}

trap "fault_trap" ERR
trap "sig_trap" SIGINT SIGTERM

logAndStop() {
  local -r errormsg="${1}"
  echo "Error! Message: ${errormsg}">&2
  exit 1
}

# Generates 2 new certificates, the second certificate will be signed by letsencrypt after the first one expires.
# This makes DANE key rollovers smooth since the upcoming key is already published. This allows for long TTLs
genCert() {
  local -r domain="${1}"
  local -r certnumbers=("${2}" "$((${2}+1))") # Current and next certnumber
  local updated=0
  local certnumber
  for certnumber in "${certnumbers[@]}"; do
    if ! isKeyAndCSRPresent "${domain}" "${certnumber}"; then
      echo "##### Generating ECDSA certificate ${certnumber} for ${domain} #####"
      openssl ecparam -genkey -name secp384r1 | openssl ec -out certs-ecc/"${domain}"-"${certnumber}"-privkey.pem
      openssl req -new -subj "/CN=${domain}" -utf8 -nodes -sha512 \
        -key certs-ecc/"${domain}"-"${certnumber}"-privkey.pem \
        -reqexts SAN \
        -config <(cat /etc/ssl/openssl.cnf \
                <(printf "\n[SAN]\nsubjectAltName=DNS:%s,DNS:*.%s" "${domain}" "${domain}")) \
        -out certs-ecc/"${domain}"-"${certnumber}".csr
      echo "##### Generating RSA certificate ${certnumber} for ${domain} #####"
      openssl req -subj "/CN=${domain}" -utf8 -nodes -sha512 \
        -newkey rsa:4096 \
        -reqexts SAN \
        -config <(cat /etc/ssl/openssl.cnf \
                <(printf "\n[SAN]\nsubjectAltName=DNS:%s,DNS:*.%s" "${domain}" "${domain}")) \
        -keyout certs-rsa/"${domain}"-"${certnumber}"-privkey.pem \
        -out certs-rsa/"${domain}"-"${certnumber}".csr 2>/dev/null
      updated=1
    fi
  done
  if [[ "${updated}" -eq 1 ]];then
    return 0
  else
    return 1
  fi
}

# Sanity check to see if the private key an CSR is present before signing
isKeyAndCSRPresent() {
  local -r domain="${1}"
  local -r certnumber="${2}"
  if [[ -f certs-ecc/"${domain}"-"${certnumber}"-privkey.pem ]] &&
  [[ -f certs-ecc/"${domain}"-"${certnumber}".csr ]] &&
  [[ -f certs-rsa/"${domain}"-"${certnumber}"-privkey.pem ]] &&
  [[ -f certs-rsa/"${domain}"-"${certnumber}".csr ]]; then
    return 0
  else
    return 1
  fi
}

# Sanity check to see if certificate is ready for use.
isCertComplete() {
  local -r domain="${1}"
  local -r certnumber="${2}"
  if isKeyAndCSRPresent "${domain}" "${certnumber}" &&
  [[ -f certs-ecc/"${domain}"-"${certnumber}"-cert.pem ]] &&
  [[ -f certs-ecc/"${domain}"-"${certnumber}"-fullchain.pem ]] &&
  [[ -f certs-rsa/"${domain}"-"${certnumber}"-cert.pem ]] &&
  [[ -f certs-rsa/"${domain}"-"${certnumber}"-fullchain.pem ]]; then
    return 0
  else
    return 1
  fi
}

# Uses certbot to sign the previously generated certificate
signCert() {
  local -r domain="${1}"
  local -r certnumber="${2}"
  if isKeyAndCSRPresent "${domain}" "${certnumber}" &&
  ! isCertComplete "${domain}" "${certnumber}"; then
    echo "##### Signing RCDSA cert ${certnumber} for domain ${domain} #####"
    certbot certonly --text --non-interactive --email "${email}" \
      --config-dir certbot-conf --work-dir certbot-work \
      --logs-dir certbot-log -d "${domain}" -d \*."${domain}" \
      --renew-by-default --agree-tos --csr certs-ecc/"${domain}"-"${certnumber}".csr \
      --dns-rfc2136 --dns-rfc2136-credentials rfc2136.ini \
      --dns-rfc2136-propagation-seconds 30 \
      --cert-path certs-ecc/"${domain}"-"${certnumber}"-cert.pem \
      --chain-path  certs-ecc/"${domain}"-"${certnumber}"-chain.pem \
      --fullchain-path certs-ecc/"${domain}"-"${certnumber}"-fullchain.pem
    chmod 640 certs-ecc/"${domain}"-"${certnumber}"-privkey.pem
    echo "##### Signing RCDSA cert ${certnumber} for domain ${domain} #####"
    certbot certonly --text --non-interactive --email "${email}" \
      --config-dir certbot-conf --work-dir certbot-work \
      --logs-dir certbot-log -d "${domain}" -d \*."${domain}" \
      --renew-by-default --agree-tos --csr certs-rsa/"${domain}"-"${certnumber}".csr \
      --dns-rfc2136 --dns-rfc2136-credentials rfc2136.ini \
      --dns-rfc2136-propagation-seconds 30 \
      --cert-path certs-rsa/"${domain}"-"${certnumber}"-cert.pem \
      --chain-path  certs-rsa/"${domain}"-"${certnumber}"-chain.pem \
      --fullchain-path certs-rsa/"${domain}"-"${certnumber}"-fullchain.pem
    chmod 640 certs-rsa/"${domain}"-"${certnumber}"-privkey.pem
    return 0
  else
    return 1
  fi
}

# Generate DANE/TLSA records from current and upcoming keys
getTLSARecords() {
  local -r domain_cert="${1}"
  local -r -a certnumber=$(getCertnumber "${domain_cert}")
  # The TLSA records that need to be added for each entry
  local tlsarecords=()
  # ECDSA
  mapfile -t -O "${#tlsarecords[@]}" tlsarecords < <(openssl x509 -noout -pubkey -in certs-ecc/"${domain_cert}"-"${certnumber}"-cert.pem 2>/dev/null \
    | openssl ec -pubin -outform DER 2>/dev/null | sha256sum | head -c 64)
  # Generate next key in advance and publish both to fix DANE key rollover
  mapfile -t -O "${#tlsarecords[@]}" tlsarecords < <(openssl x509 -noout -pubkey -in certs-ecc/"${domain_cert}"-$((certnumber+1)).csr \
    -req -signkey certs-ecc/"${domain_cert}"-$((certnumber+1))-privkey.pem 2>/dev/null | openssl ec -pubin -outform DER 2>/dev/null | sha256sum |  head -c 64)
  # RSA
  mapfile -t -O "${#tlsarecords[@]}" tlsarecords < <(openssl x509 -noout -pubkey -in certs-rsa/"${domain_cert}"-"${certnumber}"-cert.pem \
    | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | head -c 64)
  mapfile -t -O "${#tlsarecords[@]}" tlsarecords < <(openssl x509 -noout -pubkey -in certs-rsa/"${domain_cert}"-$((certnumber+1)).csr \
    -req -signkey certs-rsa/"${domain_cert}"-$((certnumber+1))-privkey.pem 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum |  head -c 64)
  echo "${tlsarecords[@]}"
  return 0
}

# Adds DANE/TLSA records to global string to be send to the DDNS server
setTLSARecords() {
  # The actual domain name, could differ because of wildcard certs/subdomains
  local -r domain_name="${1}"
  local tlsarecords
  # Rebuild array
  shift
  read -r -a tlsarecords <<< "$@"
  local nsuconfig="\nupdate delete *._tcp.${domain_name}. IN TLSA\n"
  for tlsarecord in "${tlsarecords[@]}"; do
    nsuconfig+="update add *._tcp.${domain_name}. 3600 IN TLSA 3 1 1 ${tlsarecord}\n"
  done
  echo "${nsuconfig}"
  return 0
}

# Sanity check to see if zone is really delegated to your authoritative DNS servers
CheckDomainDelegation() {
  local -r domain="${1}"
  local result
  local counter
  for externalresolver in "${externalresolvers[@]}"; do
    counter=0
    mapfile -t result < <(dig -r -q "${domain}" NS @"${externalresolver}" +short)
    for nameserver in "${nameservers[@]}"; do
      if [[ "${result[*]}" =~ ${nameserver} ]]; then
        counter=$((counter + 1))
      fi
    done
    if [[ "${#result[@]}" -ne "${#nameservers[@]}" ]] ||
    [[ "${#nameservers[@]}" -ne "${counter}" ]]; then
      logAndStop "DNS delegation failed for domain: ${domain}, resolver: ${externalresolver}, resolved: ${result[*]}."
    fi
  done
}

# Isn't shell scripting amazing
isInteger() {
  local -r input="${1}"
  if [[ "${input}" == ?(-)+([[:digit:]]) ]]; then
    return 0
  else
    logAndStop "${input} is not an integer"
  fi
}

# Yeah...
isIntegerBetween() {
  local -r input="${1}"
  local -r start="${2}"
  local -r stop="${3}"
  if isInteger "${input}" &&
  [[ "${input}" -ge "${start}" ]] &&
  [[ "${input}" -le "${stop}" ]]; then
    return 0
  else
    return 1
  fi
}

# Returns the current certificate id or 0 if there are none present.
getCertnumber() {
  local -r domain="${1}"
  if [[ -e state/"${domain}" ]]; then
    local -r certnumber=$(<state/"${domain}")
    isInteger "${certnumber}"
    echo "${certnumber}"
  else
    echo 0
  fi
}

processDomain() {
  local -r domain="${1}"
  local updated=0
  local certnumber
  CheckDomainDelegation "${domain}"
  certnumber=$(getCertnumber "${domain}")
  if isCertComplete "${domain}" "${certnumber}"; then
    local -r certvaliddaysecdsa=$(echo "(" "$(date -d "$(openssl x509 -in certs-ecc/"${domain}"-"${certnumber}"-cert.pem \
      -text -noout | grep "Not After" | cut -c 25-)" +%s)" - "$(date -d "now" +%s)" ")" / 3600 | bc)
    local -r certvaliddaysrsa=$(echo "(" "$(date -d "$(openssl x509 -in certs-rsa/"${domain}"-"${certnumber}"-cert.pem \
      -text -noout | grep "Not After" | cut -c 25-)" +%s)" - "$(date -d "now" +%s)" ")" / 3600 | bc)
    isInteger "${certvaliddaysecdsa}"
    isInteger "${certvaliddaysrsa}"
    # If there are less than 30 days remaining, renew certificate
    if [[ "${certvaliddaysecdsa}" -lt 30 ]] || [[ "${certvaliddaysrsa}" -lt 30 ]]; then
      certnumber=$((certnumber + 1))
      updated=1
    fi
  fi
  # Generate current and next certificate
  genCert "${domain}" "${certnumber}" && updated=1
  # Sign current certificate
  signCert "${domain}" "${certnumber}" && updated=1
  # See if something has changed, certnumber 0 means that the certificate is new
  if [[ "${updated}" -eq 1 ]]; then
    echo "${certnumber}" > state/"${domain}"
    # ECDSA
    ln -sf ../certs-ecc/"${domain}"-"${certnumber}"-cert.pem live-ecc/"${domain}"-cert.pem
    ln -sf ../certs-ecc/"${domain}"-"${certnumber}"-chain.pem live-ecc/"${domain}"-chain.pem
    ln -sf ../certs-ecc/"${domain}"-"${certnumber}"-fullchain.pem live-ecc/"${domain}"-fullchain.pem
    ln -sf ../certs-ecc/"${domain}"-"${certnumber}"-privkey.pem live-ecc/"${domain}"-privkey.pem
    # RSA
    ln -sf ../certs-rsa/"${domain}"-"${certnumber}"-cert.pem live-rsa/"${domain}"-cert.pem
    ln -sf ../certs-rsa/"${domain}"-"${certnumber}"-chain.pem live-rsa/"${domain}"-chain.pem
    ln -sf ../certs-rsa/"${domain}"-"${certnumber}"-fullchain.pem live-rsa/"${domain}"-fullchain.pem
    ln -sf ../certs-rsa/"${domain}"-"${certnumber}"-privkey.pem live-rsa/"${domain}"-privkey.pem
    updatedglobal=1
  fi
}

main() {
  local domain
  if [[ "$EUID" -eq 0 ]]; then
    logAndStop "Do not run as root! Stopping"
  fi
  if ! [[ -d certs-ecc ]] || ! [[ -d state ]] || ! [[ -d live-ecc ]] || ! [[ -d certs-rsa ]] || ! [[ -d live-rsa ]]; then
    logAndStop "Make sure the directories: certs-ecc state live-ecc certs-rsa live-rsa are present in $(pwd)"
  fi
  for domain in "${domains[@]}"; do
    processDomain "${domain}"
  done
  # Housekeeping if changes are made to certs
  if [[ "$updatedglobal" -eq 1 ]]; then
    # Generate and add TLSA/DANE records
    nsucommand+="server ${ddnsserver}\n"
    for subdomain in "${!subdomains[@]}"; do
      nsucommand+=$(setTLSARecords "${subdomain}" "$(getTLSARecords "${subdomains[${subdomain}]}")")
    done
    for domain_name in "${domains[@]}"; do
      nsucommand+=$(setTLSARecords "${domain_name}" "$(getTLSARecords "${domain_name}")")
    done
    nsucommand+="\nsend\nquit\n"
    echo -e "$nsucommand" | nsupdate -k acme.key
    # It's possible to restart or reload services here since it only runs when there is a new certificate.
  fi
}

main
