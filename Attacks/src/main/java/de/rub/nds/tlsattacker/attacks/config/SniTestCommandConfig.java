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
public class SniTestCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "sni_test";

    @Parameter(names = "-server_name2", description = "Servername for HostName TLS extension, used in the second ClientHello message.")
    protected String serverName2;

    public SniTestCommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
    }

    public String getServerName2() {
	return serverName2;
    }

    public void setServerName2(String serverName2) {
	this.serverName2 = serverName2;
    }
}
