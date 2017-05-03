/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola
 */
public class HKDFunctionTest {

    private HKDFunction hkdFunction;

    public HKDFunctionTest() {

    }

    @Before
    public void setUp() {
        this.hkdFunction = new HKDFunction();
    }

    @Test
    public void testHkdfExtractExpand() {
        String macAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256.getMacAlgorithm().getJavaName();
        byte[] salt = ArrayConverter.hexStringToByteArray("000102030405060708090a0b0c");
        byte[] ikm = ArrayConverter.hexStringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        int outLen = 42;
        byte[] info = ArrayConverter.hexStringToByteArray("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = ArrayConverter
                .hexStringToByteArray("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] okm = ArrayConverter
                .hexStringToByteArray("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        String labelIn = "test";
        byte[] hashValue = ArrayConverter
                .hexStringToByteArray("f9a54250131c827542664bcad131b87c09cdd92f0d5f84db3680ee4c0c0f8ed6");
        byte[] hkdfEncodedLabel = ArrayConverter
                .hexStringToByteArray("002a0d544c5320312e332c207465737420f9a54250131c827542664bcad131b87c09cdd92f0d5f84db3680ee4c0c0f8ed6");
        byte[] hkdfExpandLabel = ArrayConverter
                .hexStringToByteArray("474de877d26b9e14ba50d91657bdf8bdb0fb7152f0ef8d908bb68eb697bb64c6bf2f2d81fa987e86bc32");

        byte[] result1 = hkdFunction.hkdfExtract(macAlgorithm, salt, ikm);
        byte[] result2 = hkdFunction.hkdfExpand(macAlgorithm, result1, info, outLen);
        byte[] result3 = hkdFunction.hkdfLabelEncoder(hashValue, labelIn, outLen);
        byte[] result4 = hkdFunction.hkdfExpand(macAlgorithm, salt, result3, outLen);
        byte[] result5 = hkdFunction.hkdfExpandLabel(macAlgorithm, salt, hashValue, labelIn, outLen);

        assertArrayEquals(result1, prk);
        assertArrayEquals(result2, okm);
        assertArrayEquals(result3, hkdfEncodedLabel);
        assertArrayEquals(result4, hkdfExpandLabel);
        assertArrayEquals(result5, hkdfExpandLabel);
    }
}
