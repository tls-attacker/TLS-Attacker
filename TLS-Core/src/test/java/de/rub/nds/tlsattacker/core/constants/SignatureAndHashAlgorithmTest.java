/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import org.junit.Test;

/**
 *
 * @author robert
 */
public class SignatureAndHashAlgorithmTest {

    public SignatureAndHashAlgorithmTest() {
    }

    @Test
    public void testPrintAlgos() {
        for (SignatureAndHashAlgorithm algo : SignatureAndHashAlgorithm.values()) {
            System.out.println("---");
            System.out.println("Original Value:" + algo.name());
            System.out.println("HashAlgo:" + algo.getHashAlgorithm());
            System.out.println("Signature Value:" + algo.getSignatureAlgorithm());
        }
    }
}
