/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import java.util.LinkedList;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class BleichenbacherCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "bleichenbacher";

    public enum Type {
	FULL,
	FAST
    }

    @Parameter(names = "-type", description = "Type of the Bleichenbacher Test results in a different number of server test quries (FAST/FULL)")
    Type type;

    public BleichenbacherCommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
	type = Type.FAST;
    }

    public Type getType() {
	return type;
    }

    public void setType(Type type) {
	this.type = type;
    }
}
