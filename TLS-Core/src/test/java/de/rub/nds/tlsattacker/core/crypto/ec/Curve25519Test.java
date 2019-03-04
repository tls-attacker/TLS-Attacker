/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * Test cases from: https://tools.ietf.org/html/rfc7748#section-6.1
 */
public class Curve25519Test {

    private final static Logger LOGGER = LogManager.getLogger();

    public Curve25519Test() {
    }

    @Before
    public void setUp() {
    }

    @Test
    public void test1() {

        byte[] privateA = ArrayConverter
                .hexStringToByteArray("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] privateB = ArrayConverter
                .hexStringToByteArray("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] publicA = ArrayConverter
                .hexStringToByteArray("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] publicB = ArrayConverter
                .hexStringToByteArray("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] result = ArrayConverter
                .hexStringToByteArray("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        byte[] sharedSecretA = new byte[32];
        byte[] sharedSecretB = new byte[32];

        Curve25519.clamp(privateA);
        Curve25519.clamp(privateB);

        Curve25519.curve(sharedSecretA, privateA, publicB);
        LOGGER.debug("Aus A: " + ArrayConverter.bytesToHexString(sharedSecretA));
        Curve25519.curve(sharedSecretB, privateB, publicA);

        assertArrayEquals(result, sharedSecretA);
        assertArrayEquals(result, sharedSecretB);
    }

    @Test
    public void test2() {

        byte[] privateA = ArrayConverter
                .hexStringToByteArray("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] privateB = ArrayConverter
                .hexStringToByteArray("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] publicA = new byte[32];
        byte[] publicB = new byte[32];
        byte[] result = ArrayConverter
                .hexStringToByteArray("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        byte[] sharedSecretA = new byte[32];
        byte[] sharedSecretB = new byte[32];

        Curve25519.keygen(publicA, null, privateA);
        LOGGER.debug("Public A: " + ArrayConverter.bytesToHexString(publicA));
        Curve25519.keygen(publicB, null, privateB);
        LOGGER.debug("Public B: " + ArrayConverter.bytesToHexString(publicB));

        Curve25519.curve(sharedSecretA, privateA, publicB);
        LOGGER.debug("Aus A: " + ArrayConverter.bytesToHexString(sharedSecretA));
        Curve25519.curve(sharedSecretB, privateB, publicA);

        assertArrayEquals(result, sharedSecretA);
        assertArrayEquals(result, sharedSecretB);
    }

}
