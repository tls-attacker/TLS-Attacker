/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testsuite.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerTestSuiteConfig extends ClientCommandConfig {

    public static final String COMMAND = "testsuite_server";

    @Parameter(names = "-folder", description = "Root folder including the test cases.")
    String folder;

    public ServerTestSuiteConfig() {
        folder = "../resources/testsuite";
    }

    public String getFolder() {
        return folder;
    }

    public void setFolder(String folder) {
        this.folder = folder;
    }
}
