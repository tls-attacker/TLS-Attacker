/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agents;

import java.util.logging.Logger;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;

/**
 * A Factory class that generates the right Agent depending on the agent set in the Config.
 * @author Robert Merget - robert.merget@rub.de
 */
public class AgentFactory {

    /**
     *
     * @param config
     * @param keypair
     * @return
     */
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

    /**
     *
     */
    private AgentFactory()
    {
    }
    private static final Logger LOG = Logger.getLogger(AgentFactory.class.getName());
}
