/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testsuite.impl;

import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public abstract class TestSuite {

    public static Logger LOGGER = LogManager.getLogger("TestSuite");

    List<String> successfulTests = new LinkedList<>();
    List<String> failedTests = new LinkedList<>();

    public TestSuite() {
        successfulTests = new LinkedList<>();
        failedTests = new LinkedList<>();
    }

    public abstract boolean startTests();
}
