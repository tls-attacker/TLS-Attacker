/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class MultiFuzzerConfig {

    public static final String COMMAND = "multi_fuzzer";

    @Parameter(names = { "-h", "-help" }, help = true, description = "Prints help")
    protected boolean help;

    @Parameter(names = "-startup_command_file", required = true, description = "XML file that is used for starting the server and the fuzzer.")
    String startupCommandFile;

    public MultiFuzzerConfig() {

    }

    public String getStartupCommandFile() {
	return startupCommandFile;
    }

    public void setStartupCommandFile(String startupCommandFile) {
	this.startupCommandFile = startupCommandFile;
    }

    public boolean isHelp() {
	return help;
    }

    public void setHelp(boolean help) {
	this.help = help;
    }
}
