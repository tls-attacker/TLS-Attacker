/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.security.Security;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class MessageDigestCollectorTest {

    private MessageDigestCollector digest;
    private final byte[] testArray = {3, 0, 5, 6};

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        digest = new MessageDigestCollector();
    }

    /** Test for the Different Constructors */
    @Test
    public void constructorTest() {
        assertDoesNotThrow(MessageDigestCollector::new);
    }

    /** Test of Set/Get method, of class MessageDigestCollector. */
    @Test
    public void testSetAndGetBytes() {
        digest.setRawBytes(testArray);
        assertArrayEquals(testArray, digest.getRawBytes());
        assertDoesNotThrow(() -> digest.setRawBytes(null));
        assertArrayEquals(new byte[0], digest.getRawBytes());
    }

    /** Test of append method, of class MessageDigestCollector. */
    @Test
    @Disabled("Not implemented")
    public void testAppend() {}

    /**
     * Provides test vectors of format (providedProtocolVersion, providedCipherSuite) for {@link
     * #testDigest(ProtocolVersion, CipherSuite)}.
     */
    public static Stream<Arguments> provideDigestTestVectors() {
        return Stream.of(
                Arguments.of(ProtocolVersion.TLS10, CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA),
                Arguments.of(ProtocolVersion.TLS11, CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA),
                Arguments.of(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA),
                Arguments.of(
                        ProtocolVersion.TLS10,
                        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
                Arguments.of(
                        ProtocolVersion.TLS11,
                        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
                Arguments.of(
                        ProtocolVersion.TLS10, CipherSuite.TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384),
                Arguments.of(
                        ProtocolVersion.TLS11, CipherSuite.TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384),
                Arguments.of(
                        ProtocolVersion.TLS12, CipherSuite.TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384),
                Arguments.of(ProtocolVersion.TLS10, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM),
                Arguments.of(ProtocolVersion.TLS11, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM),
                Arguments.of(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM),
                Arguments.of(ProtocolVersion.TLS10, CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5),
                Arguments.of(ProtocolVersion.TLS11, CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5),
                Arguments.of(ProtocolVersion.TLS12, CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5),
                Arguments.of(ProtocolVersion.TLS10, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
                Arguments.of(ProtocolVersion.TLS11, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
                Arguments.of(ProtocolVersion.TLS12, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
                Arguments.of(
                        ProtocolVersion.TLS12, CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT),
                Arguments.of(
                        ProtocolVersion.TLS12, CipherSuite.TLS_GOSTR341094_WITH_NULL_GOSTR3411));
    }

    /** Test of digest method, of class MessageDigestCollector. */
    @ParameterizedTest
    @MethodSource("provideDigestTestVectors")
    public void testDigest(
            ProtocolVersion providedProtocolVersion, CipherSuite providedCipherSuite) {
        digest.setRawBytes(testArray);
        assertDoesNotThrow(() -> digest.digest(providedProtocolVersion, providedCipherSuite));
    }

    /** Test of reset method, of class MessageDigestCollector. */
    @Test
    public void testReset() {
        digest.setRawBytes(testArray);
        assertArrayEquals(testArray, digest.getRawBytes());
        digest.reset();
        assertArrayEquals(digest.getRawBytes(), new byte[0]);
    }

    /** Test of getRawBytes method, of class MessageDigestCollector. */
    @Test
    public void testGetRawBytes() {
        assertNotNull(digest.getRawBytes());
    }

    /** Test of setRawBytes method, of class MessageDigestCollector. */
    @Test
    public void testSetRawBytes() {
        digest.setRawBytes(testArray);
        assertArrayEquals(testArray, digest.getRawBytes());
    }
}
