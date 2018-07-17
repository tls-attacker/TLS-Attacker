/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.security.Security;
import java.util.Random;
import mockit.Expectations;
import mockit.Mocked;
import mockit.integration.junit4.JMockit;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(JMockit.class)
public class PseudoRandomFunctionTest {

    /**
     * Test of compute method, of class PseudoRandomFunction.
     *
     * @param mockedTlsContext
     * @param mockedParameters
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testComputeForTls12(@Mocked final TlsContext mockedTlsContext,
            @Mocked final SecurityParameters mockedParameters) throws CryptoException {
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

        Security.addProvider(new BouncyCastleProvider());
        seed = ArrayConverter.hexStringToByteArray("DD65AFF37A86CD3BECFAF84BE5C85787009FCE23DED71B513EC6F97BA44CF654C6891E4146BBE9DE33DFE9936917C47ED8810D90DDFA90CBDFFAEAD7");
        result1 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_GOSTR3411, secret, label, seed, size);
        result2 = ArrayConverter.hexStringToByteArray("49BC96FF7CB5A404DFBE1F06CFE49A01D728BDBCDA0FDD87F9B349FF9E2537959F2D0DB3C4480E2C1916D19C2FF5623D");

        assertArrayEquals(result1, result2);
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     *
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testComputeForTls11() throws CryptoException {
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
