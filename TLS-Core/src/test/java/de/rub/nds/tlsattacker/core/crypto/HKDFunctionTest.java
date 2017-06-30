/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class HKDFunctionTest {

    public HKDFunctionTest() {

    }

    @Before
    public void setUp() {
    }

    /**
     * Test of extract method, of class HKDFunction
     */
    @Test
    public void testExtractNoSalt() {
        HKDFAlgorithm hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256;
        byte[] salt = {};
        byte[] ikm = ArrayConverter
                .hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");

        byte[] result = HKDFunction.extract(hkdfAlgorithm, salt, ikm);
        byte[] resultCorrect = ArrayConverter
                .hexStringToByteArray("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        assertArrayEquals(result, resultCorrect);
    }

    /**
     * Test of extract method, of class HKDFunction
     */
    @Test
    public void testExtractWithSalt() {
        HKDFAlgorithm hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256;
        byte[] salt = ArrayConverter
                .hexStringToByteArray("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        byte[] ikm = ArrayConverter
                .hexStringToByteArray("c08acc73ba101d7fea86d223de32d9fc4948e145493680594b83b0a109f83649");

        byte[] result = HKDFunction.extract(hkdfAlgorithm, salt, ikm);
        byte[] resultCorrect = ArrayConverter
                .hexStringToByteArray("31168cad69862a80c6f6bfd42897d0fe23c406a12e652a8d3ae4217694f49844");
        assertArrayEquals(result, resultCorrect);
    }

    /**
     * Test of deriveSecret method, of class HKDFunction
     */
    @Test
    public void testDeriveSecret() {
        HKDFAlgorithm hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256;
        String hashAlgorithm = DigestAlgorithm.SHA256.getJavaName();
        byte[] prk = ArrayConverter
                .hexStringToByteArray("33AD0A1C607EC03B09E6CD9893680CE210ADF300AA1F2660E1B22E10F170F92A");
        byte[] toHash = ArrayConverter.hexStringToByteArray("");
        String labelIn = HKDFunction.DERIVED;

        byte[] result = HKDFunction.deriveSecret(hkdfAlgorithm, hashAlgorithm, prk, labelIn, toHash);
        byte[] resultCorrect = ArrayConverter
                .hexStringToByteArray("6F2615A108C702C5678F54FC9DBAB69716C076189C48250CEBEAC3576C3611BA");
        assertArrayEquals(result, resultCorrect);
    }

    /**
     * Test of expandLabel method, of class HKDFunction
     */
    @Test
    public void testExpandLabel() {
        HKDFAlgorithm hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256;
        byte[] prk = ArrayConverter
                .hexStringToByteArray("E056D47C7DB9C04BBECE6AC9525163DE72B7D25B6B0899366F8FA741A5C01709");
        byte[] hashValue = ArrayConverter.hexStringToByteArray("");
        String labelIn = HKDFunction.KEY;
        int outLen = 16;

        byte[] result = HKDFunction.expandLabel(hkdfAlgorithm, prk, labelIn, hashValue, outLen);
        byte[] resultCorrect = ArrayConverter.hexStringToByteArray("04C5DA6EC39FC1653E085FA83E51C6AF");
        assertArrayEquals(result, resultCorrect);
    }
}
