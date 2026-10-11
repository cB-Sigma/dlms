#!/bin/sh
# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside the maven container started by interop_test.go: fetches
# Gurux.DLMS.Java at the commit given as $1, builds its unmodified server
# example (which takes gurux.dlms from Maven Central at the version its
# pom names) and starts it on ports 4060 to 4064. Nothing from Gurux is
# kept in this repository.
#
# One setting is changed for the wrapper port (4063) only, through the
# settings file the example writes on its first start and reads on the
# next: its HLS-GMAC association (client 21) is given the logical-name-with-ciphering application
# context and the security setup object of its ciphered association
# (0.0.43.0.8.255, suite 0, the server's global keys), so that it takes
# authenticated and encrypted APDUs. Out of the box (as on the HDLC port,
# 4061) it only takes the context without ciphering and plain APDUs. Its
# HLS-SHA256 association (client 22) gets the ciphering context and the
# example's security setup of security suite 1 (0.0.43.0.7.255, made for
# its ECDSA association), so suite 1 ciphering is checked too.
set -eu
commit="$1"
cd /tmp
curl -fsSL -o gurux.tar.gz "https://github.com/Gurux/Gurux.DLMS.Java/archive/${commit}.tar.gz"
tar xzf gurux.tar.gz
cd "gurux.dlms.java-${commit}/gurux.dlms.server.example.java"
mvn -q -B -DskipTests package
jar=target/gurux.dlms.server.example.java-0.0.1-SNAPSHOT.jar
echo "sigma: gurux server built"

java -jar "$jar" -p 4060 -t Off </dev/null >/dev/null 2>&1 &
first=$!
n=0
until [ -s 4064settings.xml ]; do
	n=$((n + 1))
	if [ "$n" -gt 120 ]; then
		echo "sigma: the example wrote no settings"
		exit 1
	fi
	sleep 1
done
sleep 3
kill "$first"
wait "$first" || true
for f in 4063settings.xml; do
	sed -i -e '/<ClientSAP>21<\/ClientSAP>/,/<\/GXDLMSAssociationLogicalName>/ s#<ContextId>1</ContextId>#<ContextId>3</ContextId>#' \
		-e '/<ClientSAP>21<\/ClientSAP>/,/<\/GXDLMSAssociationLogicalName>/ s#<Users>#<SecuritySetupReference>0.0.43.0.8.255</SecuritySetupReference><Users>#' \
		-e '/<ClientSAP>22<\/ClientSAP>/,/<\/GXDLMSAssociationLogicalName>/ s#<ContextId>1</ContextId>#<ContextId>3</ContextId>#' \
		-e '/<ClientSAP>22<\/ClientSAP>/,/<\/GXDLMSAssociationLogicalName>/ s#<Users>#<SecuritySetupReference>0.0.43.0.7.255</SecuritySetupReference><Users>#' "$f"
done
echo "sigma: client 21 (HLS-GMAC) on the wrapper set to the ciphering context with security setup 0.0.43.0.8.255; client 22 (HLS-SHA256) to the ciphering context with security setup 0.0.43.0.7.255 (suite 1); HDLC keeps the defaults"
exec java -jar "$jar" -p 4060 -t Info
