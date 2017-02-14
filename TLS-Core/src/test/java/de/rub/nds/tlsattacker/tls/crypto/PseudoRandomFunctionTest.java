/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import java.util.Random;
import mockit.Expectations;
import mockit.Mocked;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsUtils;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class PseudoRandomFunctionTest {

    public PseudoRandomFunctionTest() {
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     * 
     * @param mockedTlsContext
     * @param mockedParameters
     */
    @Test
    public void testComputeForTls12(@Mocked final TlsContext mockedTlsContext,
            @Mocked final SecurityParameters mockedParameters) {
        // Record expectations if/as needed:
        new Expectations() {
            {
                mockedTlsContext.getServerVersion();
                result = ProtocolVersion.TLSv12;
            }
            {
                mockedTlsContext.getSecurityParameters();
                result = mockedParameters;
            }
            {
                mockedParameters.getPrfAlgorithm();
                result = 1;
            }
        };

        byte[] secret = new byte[48];
        String label = "master secret";
        byte[] seed = new byte[60];
        Random r = new Random();
        r.nextBytes(seed);
        int size = 48;

        byte[] result1 = TlsUtils.PRF(mockedTlsContext, secret, label, seed, size);
        byte[] result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_SHA256, secret, label, seed, size);

        assertArrayEquals(result1, result2);

        new Expectations() {
            {
                mockedParameters.getPrfAlgorithm();
                result = 2;
            }
        };

        result1 = TlsUtils.PRF(mockedTlsContext, secret, label, seed, size);
        result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_SHA384, secret, label, seed, size);

        assertArrayEquals(result1, result2);
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     */
    @Test
    public void testComputeForTls11() {
        byte[] secret = new byte[48];
        String label = "master secret";
        byte[] seed = new byte[60];
        Random r = new Random();
        r.nextBytes(seed);
        int size = 48;

        byte[] result1 = TlsUtils.PRF_legacy(secret, label, seed, size);

        byte[] result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_LEGACY, secret, label, seed, size);

        assertArrayEquals(result1, result2);
    }
}
