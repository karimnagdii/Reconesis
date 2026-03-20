#!/bin/bash
set -e

# Install socat if not already present (osixia/openldap base is Debian)
if ! command -v socat >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq socat
fi

# Socat stubs for non-LDAP AD ports
socat TCP-LISTEN:53,fork,reuseaddr   EXEC:'printf "DNS-ready\r\n"' &
socat TCP-LISTEN:88,fork,reuseaddr   EXEC:'printf "Kerberos v5 ready\r\n"' &
socat TCP-LISTEN:135,fork,reuseaddr  EXEC:'printf "MSRPC endpoint mapper ready\r\n"' &
socat TCP-LISTEN:445,fork,reuseaddr  EXEC:'printf "SMB signing: required\r\n"' &
socat TCP-LISTEN:3268,fork,reuseaddr EXEC:'printf "LDAP Global Catalog ready\r\n"' &

# Hand off to the real openldap entrypoint (PID 1; container exits if openldap crashes)
exec /bin/bash /container/tool/run --copy-service
