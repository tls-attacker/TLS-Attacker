#!/bin/bash

/usr/lib/jvm/jdk1.8.0_05/bin/java -cp target/TLS-Server-1.0-SNAPSHOT-jar-with-dependencies.jar -Djavax.net.debug=SSL,handshake  de.rub.nds.tlsattacker.tlsserver.TLSServer server-2048.jks password TLS 51624
