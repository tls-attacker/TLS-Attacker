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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola
 */
public class HKDFunctionTest {

    public HKDFunctionTest() {

    }

    @Before
    public void setUp() {
    }

    @Test
    public void testExtractNoSalt() {
        String macAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256.getMacAlgorithm().getJavaName();
        byte[] salt = {};
        byte[] ikm = ArrayConverter
                .hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");

        byte[] result = HKDFunction.extract(macAlgorithm, salt, ikm);
        byte[] resultCorrect = ArrayConverter
                .hexStringToByteArray("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        assertArrayEquals(result, resultCorrect);
    }

    @Test
    public void testExtractWithSalt() {
        String macAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256.getMacAlgorithm().getJavaName();
        byte[] salt = ArrayConverter
                .hexStringToByteArray("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        byte[] ikm = ArrayConverter
                .hexStringToByteArray("c08acc73ba101d7fea86d223de32d9fc4948e145493680594b83b0a109f83649");

        byte[] result = HKDFunction.extract(macAlgorithm, salt, ikm);
        byte[] resultCorrect = ArrayConverter
                .hexStringToByteArray("31168cad69862a80c6f6bfd42897d0fe23c406a12e652a8d3ae4217694f49844");
        assertArrayEquals(result, resultCorrect);
    }

    @Test
    public void testDeriveSecret() {
        String macAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256.getMacAlgorithm().getJavaName();
        byte[] prk = ArrayConverter
                .hexStringToByteArray("31168cad69862a80c6f6bfd42897d0fe23c406a12e652a8d3ae4217694f49844");
        byte[] hashValue = ArrayConverter
                .hexStringToByteArray("52c04472bdfe929772c98b91cf425f78f47659be9d4a7d68b9e29d162935e9b9");
        String labelIn = "client handshake traffic secret";

        byte[] result = HKDFunction.deriveSecret(macAlgorithm, prk, labelIn, hashValue);
        byte[] resultCorrect = ArrayConverter
                .hexStringToByteArray("6c6f274b1eae09b8bbd2039b7eb56147201a5e19288a3fd504fa52b1178a6e93");
        assertArrayEquals(result, resultCorrect);
    }

    @Test
    public void testExpandLabel() {
        String macAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256.getMacAlgorithm().getJavaName();
        byte[] prk = ArrayConverter
                .hexStringToByteArray("b2c2663ed59e833b17c68823516f11f1cb311855045d3ce46bfe8ac8889268d9");
        byte[] hashValue = ArrayConverter.hexStringToByteArray("");
        String labelIn = HKDFunction.IV;
        int outLen = 12;

        byte[] result = HKDFunction.expandLabel(macAlgorithm, prk, labelIn, hashValue, outLen);
        byte[] resultCorrect = ArrayConverter.hexStringToByteArray("a353bfcdf9695a2a09c2e293");
        assertArrayEquals(result, resultCorrect);
    }
}
