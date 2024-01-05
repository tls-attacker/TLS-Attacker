/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

public class SignatureAndHashAlgorithmTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Test
    public void testPrintAlgos() {
        for (SignatureAndHashAlgorithm algo : SignatureAndHashAlgorithm.values()) {
            LOGGER.debug("---");
            LOGGER.debug("Original Value:" + algo.name());
            LOGGER.debug("HashAlgo:" + algo.getHashAlgorithm());
        }
    }
}
