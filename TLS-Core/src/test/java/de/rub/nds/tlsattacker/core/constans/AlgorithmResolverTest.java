/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constans;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola
 */
public class AlgorithmResolverTest {

    public AlgorithmResolverTest() {
    }

    @Before
    public void setUp() {
    }

    @Test
    public void testGetHKDFAlgorithm() {
        CipherSuite cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        HKDFAlgorithm result = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        HKDFAlgorithm result_correct = HKDFAlgorithm.TLS_HKDF_SHA256;
        assertTrue(result == result_correct);
    }

}
