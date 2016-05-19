/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ConfigHandlerFactory {

    private ConfigHandlerFactory() {

    }

    public static ConfigHandler createConfigHandler(String command) {
	switch (command) {
	    case ClientCommandConfig.COMMAND:
		return new ClientConfigHandler();
	    case ServerCommandConfig.COMMAND:
		return new ServerConfigHandler();
	    default:
		throw new UnsupportedOperationException("You have to select one of the available commands");

	}
    }
}
