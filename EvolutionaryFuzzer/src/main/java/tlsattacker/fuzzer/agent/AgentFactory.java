/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agent;

import java.util.logging.Logger;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;
import tlsattacker.fuzzer.exceptions.IllegalAgentException;

/**
 * A Factory class that generates the right Agent depending on the agent set in
 * the Config.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AgentFactory {

    /**
     * Generates the correct Agent depending on the agent field set in the
     * configuration
     * 
     * @param config
     *            The configuration object
     * @param keypair
     *            The server certificate key pair the agent should be created
     *            with
     * @return A newly generated Agent
     */
    public static Agent generateAgent(FuzzerGeneralConfig config, ServerCertificateStructure keypair)
            throws IllegalAgentException {
        switch (config.getAgent()) {
            case AFLAgent.optionName:
                return new AFLAgent(keypair);
            case PINAgent.optionName:
                return new PINAgent(config ,keypair);
            case BlindAgent.optionName:
                return new BlindAgent(keypair);
            default:
                throw new IllegalAgentException("Could not find Agent!");
        }
    }

    /**
     * Private constructor
     */
    private AgentFactory() {
    }

    private static final Logger LOG = Logger.getLogger(AgentFactory.class.getName());
}
