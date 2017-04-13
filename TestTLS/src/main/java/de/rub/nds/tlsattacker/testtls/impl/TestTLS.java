/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.impl;

import de.rub.nds.tlsattacker.testtls.policy.TlsPeerProperties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public abstract class TestTLS {

    protected static Logger LOGGER = LogManager.getLogger(HandshakeTest.class);

    protected String result;

    public TestTLS() {
    }

    public abstract void startTests();

    public String getResult() {
        return result;
    }

    public abstract void fillTlsPeerProperties(TlsPeerProperties properties);

}
