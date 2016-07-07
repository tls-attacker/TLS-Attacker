/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import java.util.LinkedList;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Cve20162107CommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "cve20162107";

    public Cve20162107CommandConfig() {
	cipherSuites = new LinkedList<>();
	protocolVersion = null;
    }

}
