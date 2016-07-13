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

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AgentFactory {

    public static Agent generateAgent(EvolutionaryFuzzerConfig config) {
	switch (config.getAgent()) {
	    case "AFL":
		return new AFLAgent();
	    case "PIN":
		return new PinAgent();
	    default:
		throw new RuntimeException("Could not find Agent!");
	}
    }
}
