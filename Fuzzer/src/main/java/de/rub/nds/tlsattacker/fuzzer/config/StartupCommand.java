/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.fuzzer.config;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
public class StartupCommand {
    private String serverCommandParameters;

    private String fuzzerCommand;

    private String shortName;

    public String getServerCommandParameters() {
	return serverCommandParameters;
    }

    public void setServerCommandParameters(String serverCommandParameters) {
	this.serverCommandParameters = serverCommandParameters;
    }

    public String getFuzzerCommand() {
	return fuzzerCommand;
    }

    public void setFuzzerCommand(String fuzzerCommand) {
	this.fuzzerCommand = fuzzerCommand;
    }

    public String getShortName() {
	return shortName;
    }

    public void setShortName(String shortName) {
	this.shortName = shortName;
    }
}
