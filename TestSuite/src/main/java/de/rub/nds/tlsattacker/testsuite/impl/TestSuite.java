/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testsuite.impl;

import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public abstract class TestSuite {

    GeneralConfig generalConfig;

    List<String> successfulTests = new LinkedList<>();
    List<String> failedTests = new LinkedList<>();

    public TestSuite(GeneralConfig config) {
        this.generalConfig = config;
        successfulTests = new LinkedList<>();
        failedTests = new LinkedList<>();
    }

    public abstract boolean startTests();
}
