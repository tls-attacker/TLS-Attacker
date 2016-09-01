/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Agents;

import Agents.Agent;
import Config.EvolutionaryFuzzerConfig;
import Certificate.ServerCertificateStructure;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AgentFactory {

    public static Agent generateAgent(EvolutionaryFuzzerConfig config, ServerCertificateStructure keypair) {
	switch (config.getAgent()) {
	    case "AFL":
		return new AFLAgent(keypair);
	    case "PIN":
		return new PINAgent(keypair);
	    case "BLIND":
		return new PINAgent(keypair);
	    default:
		throw new RuntimeException("Could not find Agent!");
	}
    }
}
