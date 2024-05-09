#!/usr/bin/env bash
set -Eeuo pipefail

source conf/config

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
  echo "Error! ${errormsg}">&2
  exit 1
}

# Generates 2 new certificates, the second certificate will be signed by letsencrypt after the first one expires.
# This makes DANE key rollovers smooth since the upcoming key is already published. This allows for long TTLs
genCert() {
  local -r domain="${1}"
  local -r certnumbers=("${2}" "$((${2}+1))") # Current and next certnumber
  local -r type="${3}"
  local updated=0
  local certnumber
  for certnumber in "${certnumbers[@]}"; do
    if ! isKeyAndCSRPresent "${domain}" "${certnumber}" "${type}"; then
      echo "##### Generating ${type} certificate ${certnumber} for ${domain} #####"
      if [[ "${type}" == "ecc" ]]; then
        openssl ecparam -genkey -name secp384r1 | openssl ec -out certs-"${type}"/"${domain}"-"${certnumber}"-privkey.pem
        openssl req -new -subj "/CN=${domain}" -utf8 -nodes \
          -key certs-"${type}"/"${domain}"-"${certnumber}"-privkey.pem -reqexts SAN \
          -config <(cat /etc/ssl/openssl.cnf \
                  <(printf "\n[SAN]\nsubjectAltName=DNS:%s,DNS:*.%s" "${domain}" "${domain}")) \
          -out certs-"${type}"/"${domain}"-"${certnumber}".csr
      elif [[ "${type}" == "rsa" ]]; then
        openssl req -newkey rsa:4096 -subj "/CN=${domain}" -utf8 -nodes -reqexts SAN \
          -config <(cat /etc/ssl/openssl.cnf \
                  <(printf "\n[SAN]\nsubjectAltName=DNS:%s,DNS:*.%s" "${domain}" "${domain}")) \
          -keyout certs-"${type}"/"${domain}"-"${certnumber}"-privkey.pem \
          -out certs-"${type}"/"${domain}"-"${certnumber}".csr
      else
        logAndStop "${type} is unknown."
      fi
      updated=1
    fi
  done
  if [[ "${updated}" -eq 1 ]]; then
    return 0
  else
    return 1
  fi
}

# Sanity check to see if the private key an CSR is present before signing
isKeyAndCSRPresent() {
  local -r domain="${1}"
  local -r certnumber="${2}"
  local -r type="${3}"
  if [[ -f certs-"${type}"/"${domain}"-"${certnumber}"-privkey.pem ]] &&
  [[ -f certs-"${type}"/"${domain}"-"${certnumber}".csr ]]; then
    return 0
  else
    return 1
  fi
}

# Sanity check to see if certificate is ready for use.
isCertComplete() {
  local -r domain="${1}"
  local -r certnumber="${2}"
  local -r type="${3}"
  if isKeyAndCSRPresent "${domain}" "${certnumber}" "${type}" &&
  [[ -f certs-"${type}"/"${domain}"-"${certnumber}"-cert.pem ]] &&
  [[ -f certs-"${type}"/"${domain}"-"${certnumber}"-fullchain.pem ]]; then
    return 0
  else
    return 1
  fi
}

# Uses certbot to sign the previously generated certificate
signCert() {
  local -r domain="${1}"
  local -r certnumber="${2}"
  local -r type="${3}"
  if isKeyAndCSRPresent "${domain}" "${certnumber}" "${type}" &&
  ! isCertComplete "${domain}" "${certnumber}" "${type}"; then
    echo "##### Signing ${type} cert ${certnumber} for domain ${domain} #####"
    # Remove failed attempt remnants
    rm -f certs-"${type}"/"${domain}"-"${certnumber}"-cert.pem
    rm -f certs-"${type}"/"${domain}"-"${certnumber}"-chain.pem
    rm -f certs-"${type}"/"${domain}"-"${certnumber}"-fullchain.pem
    certbot certonly --text --non-interactive \
      --email "${email}" --no-eff-email \
      --config-dir certbot-conf --work-dir certbot-work \
      --logs-dir certbot-log -d "${domain}" -d \*."${domain}" \
      --renew-by-default --agree-tos --csr certs-"${type}"/"${domain}"-"${certnumber}".csr \
      --dns-rfc2136 --dns-rfc2136-credentials conf/certbot-nsupdate-rfc2136.ini \
      --dns-rfc2136-propagation-seconds 15 \
      --cert-path certs-"${type}"/"${domain}"-"${certnumber}"-cert.pem \
      --chain-path  certs-"${type}"/"${domain}"-"${certnumber}"-chain.pem \
      --fullchain-path certs-"${type}"/"${domain}"-"${certnumber}"-fullchain.pem
    chmod 640 certs-"${type}"/"${domain}"-"${certnumber}"-privkey.pem
    cat "${dhparamfile}" >> certs-"${type}"/"${domain}"-"${certnumber}"-fullchain.pem
    return 0
  else
    return 1
  fi
}

# Generate DANE/TLSA records from current and upcoming keys
generateTLSARecords() {
  local -r domain_cert="${1}"
  local -r -a certnumber=$(getCertnumber "${domain_cert}")
  # The TLSA records that need to be added for each entry
  local tlsarecords=()
  # ECDSA
  mapfile -t -O "${#tlsarecords[@]}" tlsarecords < <(openssl x509 -noout -pubkey -in certs-ecc/"${domain_cert}"-"${certnumber}"-cert.pem 2>/dev/null \
    | openssl ec -pubin -outform DER 2>/dev/null | sha256sum | head -c 64)
  # Generate next key in advance and publish both for key rollover
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

# Isn't shell scripting amazing
isInteger() {
  local -r input="${1}"
  if [[ "${input}" == ?(-)+([[:digit:]]) ]]; then
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
    if isInteger "${certnumber}"; then
      echo "${certnumber}"
    else
      logAndStop "${domain} certnumber: ${certnumber} is not an integer"
    fi
  else
    echo 0
  fi
}

getOCSPStaple() {
  local -r domain="${1}"
  local -r certnumber="${2}"
  local -r type="${3}"
  ocsptool --ask \
           --load-issuer certs-"${type}"/"${domain}"-"${certnumber}"-chain.pem \
           --load-cert certs-"${type}"/"${domain}"-"${certnumber}"-cert.pem \
           --outfile ocsp/"${type}"-"${domain}".ocsp >/dev/null
}

processDomain() {
  local -r domain="${1}"
  local updated=0
  local certnumber
  local type
  local -r thirtydays=2592000
  certnumber=$(getCertnumber "${domain}")
  if isCertComplete "${domain}" "${certnumber}" "rsa" && isCertComplete "${domain}" "${certnumber}" "ecc"; then
    if ! openssl x509 -enddate -noout -in certs-rsa/"${domain}"-"${certnumber}"-cert.pem -checkend "${thirtydays}" >/dev/null || \
    ! openssl x509 -enddate -noout -in certs-ecc/"${domain}"-"${certnumber}"-cert.pem -checkend "${thirtydays}" >/dev/null;then
      certnumber=$((certnumber + 1))
      echo "${domain}: RSA or ECC cert is valid for <30 days. Renewing both"
    fi
  else
    echo "${domain}: RSA or ECC certificate is incomplete, generating and signing new certs"
  fi
  for type in "ecc" "rsa"; do
    # Generate current and next certificate
    genCert "${domain}" "${certnumber}" "${type}" && updated=1
    # Sign current certificate
    signCert "${domain}" "${certnumber}" "${type}" && updated=1
    # See if something has changed, certnumber 0 means that the certificate is new
    if [[ "${updated}" -eq 1 ]]; then
      echo "${certnumber}" > state/"${domain}"
      rm -f ocsp/"${type}"-"${domain}".ocsp
      ln -sf ../certs-"${type}"/"${domain}"-"${certnumber}"-cert.pem live-"${type}"/"${domain}"-cert.pem
      ln -sf ../certs-"${type}"/"${domain}"-"${certnumber}"-chain.pem live-"${type}"/"${domain}"-chain.pem
      ln -sf ../certs-"${type}"/"${domain}"-"${certnumber}"-fullchain.pem live-"${type}"/"${domain}"-fullchain.pem
      ln -sf ../certs-"${type}"/"${domain}"-"${certnumber}"-privkey.pem live-"${type}"/"${domain}"-privkey.pem
      updatedglobal=1
    fi
    # Always refresh OCSP staple
    getOCSPStaple "${domain}" "${certnumber}" "${type}"
    # Verify correctly set up certificates
    if ! isCertComplete "${domain}" "${certnumber}" "${type}"; then
      logAndStop "${domain}: Certificate is incomplete! type: ${type} certnumber: ${certnumber}"
    fi
  done
  # Reboot most services only when the main certificate is replaced
  #if [[ "${domain}" == "${domains[0]}" ]] && [[ "${updatedglobal}" -eq 1 ]]; then
    # TODO: Post hook after non-main cert is renewed
    #sudo /bin/systemctl restart dovecot postfix asterisk chrony
  #fi
}

main() {
  local domain
  mkdir -p certs-ecc state live-ecc certs-rsa live-rsa ocsp
  if ! [[ -f conf/nsupdate-rfc2136.key ]] || ! [[ -f conf/certbot-nsupdate-rfc2136.ini ]]; then
    logAndStop "Files missing in $(pwd)"
  fi
  for domain in "${domains[@]}"; do
    processDomain "${domain}"
  done
  # TODO: OCSP post-renewal hook
  #sudo /bin/systemctl reload dnsdist
  # Housekeeping if changes are made to certs
  if [[ "$updatedglobal" -eq 1 ]]; then
    # Generate and add TLSA records to DNS
    local nsucommand+="server ${ddnsserver}\n"

    for subdomain in "${!subdomains[@]}"; do
      nsucommand+=$(setTLSARecords "${subdomain}" "$(generateTLSARecords "${subdomains[${subdomain}]}")")
    done
    for domain_name in "${domains[@]}"; do
      nsucommand+=$(setTLSARecords "${domain_name}" "$(generateTLSARecords "${domain_name}")")
      nsucommand+=$(setTLSARecords www."${domain_name}" "$(generateTLSARecords "${domain_name}")")
    done
    nsucommand+="\nsend\nquit\n"
    echo -e "$nsucommand" | nsupdate -k conf/nsupdate-rfc2136.key
    # TODO: Add tasks to be performed after cert rotation
    #sudo /bin/systemctl reload apache2
  else
    echo "No certificates changed."
  fi
}

if [[ "$EUID" -eq 0 ]]; then
  logAndStop "Do not run as root! Stopping"
fi

main
