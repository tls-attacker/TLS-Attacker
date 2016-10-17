/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agents;

import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AgentFactory {

    public static Agent generateAgent(FuzzerGeneralConfig config, ServerCertificateStructure keypair) {
	switch (config.getAgent()) {
	    case AFLAgent.optionName:
		return new AFLAgent(keypair);
	    case PINAgent.optionName:
		return new PINAgent(keypair);
	    case BlindAgent.optionName:
		return new BlindAgent(keypair);
	    default:
		throw new RuntimeException("Could not find Agent!");
	}
    }
}
