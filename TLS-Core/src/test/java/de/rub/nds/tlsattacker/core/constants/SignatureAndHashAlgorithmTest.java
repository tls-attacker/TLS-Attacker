/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

/**
 *
 *
 */
public class SignatureAndHashAlgorithmTest {

    private final static Logger LOGGER = LogManager.getLogger();

    public SignatureAndHashAlgorithmTest() {
    }

    @Test
    public void testPrintAlgos() {
        for (SignatureAndHashAlgorithm algo : SignatureAndHashAlgorithm.values()) {
            LOGGER.debug("---");
            LOGGER.debug("Original Value:" + algo.name());
            LOGGER.debug("HashAlgo:" + algo.getHashAlgorithm());
        }
    }
}
