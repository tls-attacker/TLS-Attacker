package de.rub.nds.tlsattacker.attacks.config;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import java.util.LinkedList;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class BleichenbacherTestCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "bleichenbacher_test";

    public BleichenbacherTestCommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
    }
}
