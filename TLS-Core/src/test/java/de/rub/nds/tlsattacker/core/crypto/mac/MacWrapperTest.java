/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.mac;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.BeforeClass;
import org.junit.Test;

public class MacWrapperTest {

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSha1() throws NoSuchAlgorithmException {
        WrappedMac mac = MacWrapper.getMac(ProtocolVersion.TLS10, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
                new byte[20]);

        assertEquals(MacAlgorithm.HMAC_SHA1.getSize(), mac.getMacLength());
        byte[] actual = mac.calculateMac("Test data".getBytes());
        byte[] expected = ArrayConverter.hexStringToByteArray("2C667D86C1F63F00E86310B3A32F2D44DF34A316");
        assertArrayEquals(expected, actual);
    }

    @Test
    public void testGOST3411() throws NoSuchAlgorithmException {
        WrappedMac mac = MacWrapper.getMac(ProtocolVersion.TLS10, CipherSuite.TLS_GOSTR341094_WITH_NULL_GOSTR3411,
                new byte[32]);
        assertEquals(MacAlgorithm.HMAC_GOSTR3411.getSize(), mac.getMacLength());

        byte[] actual = mac.calculateMac("Test data".getBytes());
        byte[] expected = ArrayConverter
                .hexStringToByteArray("9E1A18525244994DF9D9006D057B4CA01093458D40DA788A91E6324278E575DF");
        assertArrayEquals(expected, actual);

        actual = mac.calculateMac(" extended".getBytes());
        expected = ArrayConverter
                .hexStringToByteArray("C0ECFFEA5D7021D84C74227D7A7E80C2C6BD5F3C5F298E904AF9A4BA5C5E5AEF");
        assertArrayEquals(expected, actual);
    }

    @Test
    public void testGOST28147IMIT() throws NoSuchAlgorithmException {
        WrappedMac mac = MacWrapper.getMac(ProtocolVersion.TLS12, CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT,
                new byte[32]);
        assertEquals(MacAlgorithm.IMIT_GOST28147.getSize(), mac.getMacLength());

        byte[] actual = mac.calculateMac("Test data".getBytes());
        byte[] expected = ArrayConverter.hexStringToByteArray("2664CBA8");
        assertArrayEquals(expected, actual);

        actual = mac.calculateMac(" extended".getBytes());
        expected = ArrayConverter.hexStringToByteArray("9E80F481");
        assertArrayEquals(expected, actual);
    }

}
