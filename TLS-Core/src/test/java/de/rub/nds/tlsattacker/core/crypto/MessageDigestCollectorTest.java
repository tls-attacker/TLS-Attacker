/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.security.Security;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class MessageDigestCollectorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    private MessageDigestCollector digest; // TLS10
    private final int testAlgorithm1Length = 16;
    private final int testAlgorithm2Length = 20;
    private final int testAlgorithm3Length = 32;
    private final byte[] testarray = { 3, 0, 5, 6 };
    private final byte[] testarray2 = { 1, 2, 3, 4, 5, 6, 7 };

    /**
     * Test for the Different Constructors
     */
    @Test
    public void constructorTest() {
        LOGGER.info("testConstructors");
        new MessageDigestCollector();
    }

    @Before
    public void setUp() {
        digest = new MessageDigestCollector();
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Test of Set/Get method, of class MessageDigestCollector.
     */
    @Test
    public void testSetandGetBytes() {
        LOGGER.info("testSetAndGet");
        byte[] testarray = { 3, 0, 5, 6 };
        digest.setRawBytes(testarray);
        assertArrayEquals(testarray, digest.getRawBytes());
        Exception ex = null;
        try {
            digest.setRawBytes(null);
        } catch (Exception E) {
            ex = E;
        }
        assertNull(ex);
    }

    /**
     * Test of append method, of class MessageDigestCollector.
     */
    @Test
    public void testAppend() {
    }

    /**
     * Test of digest method, of class MessageDigestCollector.
     */
    @Test
    public void testDigest() {
        digest.setRawBytes(testarray);
        digest.digest(ProtocolVersion.TLS10, CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        digest.digest(ProtocolVersion.TLS11, CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        digest.digest(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        digest.digest(ProtocolVersion.TLS10, CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        digest.digest(ProtocolVersion.TLS11, CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        digest.digest(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        digest.digest(ProtocolVersion.TLS10, CipherSuite.TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384);
        digest.digest(ProtocolVersion.TLS11, CipherSuite.TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384);
        digest.digest(ProtocolVersion.TLS12, CipherSuite.TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384);
        digest.digest(ProtocolVersion.TLS10, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM);
        digest.digest(ProtocolVersion.TLS11, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM);
        digest.digest(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM);
        digest.digest(ProtocolVersion.TLS10, CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5);
        digest.digest(ProtocolVersion.TLS11, CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5);
        digest.digest(ProtocolVersion.TLS12, CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5);
        digest.digest(ProtocolVersion.TLS10, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
        digest.digest(ProtocolVersion.TLS11, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
        digest.digest(ProtocolVersion.TLS12, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

        Security.addProvider(new BouncyCastleProvider());
        digest.digest(ProtocolVersion.TLS12, CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT);
        digest.digest(ProtocolVersion.TLS12, CipherSuite.TLS_GOSTR341094_WITH_NULL_GOSTR3411);
    }

    /**
     * Test of reset method, of class MessageDigestCollector.
     */
    @Test
    public void testReset() {
        digest.setRawBytes(testarray);
        assertArrayEquals(testarray, digest.getRawBytes());
        digest.reset();
        assertArrayEquals(digest.getRawBytes(), new byte[0]);
    }

    /**
     * Test of getRawBytes method, of class MessageDigestCollector.
     */
    @Test
    public void testGetRawBytes() {
        assertNotNull(digest.getRawBytes());
    }

    /**
     * Test of setRawBytes method, of class MessageDigestCollector.
     */
    @Test
    public void testSetRawBytes() {
        digest.setRawBytes(testarray);
        assertArrayEquals(testarray, digest.getRawBytes());
    }
}
