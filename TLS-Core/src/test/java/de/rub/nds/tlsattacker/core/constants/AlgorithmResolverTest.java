/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import static org.junit.jupiter.api.Assertions.*;

import java.util.stream.Stream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

public class AlgorithmResolverTest {

    /**
     * Provides test vectors of format (providedProtocolVersion, providedCipherSuite,
     * expectedPRFAlgorithm) for {@link #testGetPRFAlgorithm(ProtocolVersion, CipherSuite,
     * PRFAlgorithm)}
     */
    public static Stream<Arguments> provideGetPRFAlgorithmTestVectors() {
        Stream.Builder<Arguments> streamBuilder = Stream.builder();
        // Some protocol versions should always return tls_legacy
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("GOST")) {
                continue;
            }
            streamBuilder.add(
                    Arguments.of(ProtocolVersion.TLS10, suite, PRFAlgorithm.TLS_PRF_LEGACY));
            streamBuilder.add(
                    Arguments.of(ProtocolVersion.TLS11, suite, PRFAlgorithm.TLS_PRF_LEGACY));
            streamBuilder.add(
                    Arguments.of(ProtocolVersion.DTLS10, suite, PRFAlgorithm.TLS_PRF_LEGACY));
        }
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                        PRFAlgorithm.TLS_PRF_SHA384));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.DTLS12,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                        PRFAlgorithm.TLS_PRF_SHA384));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        PRFAlgorithm.TLS_PRF_SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.DTLS12,
                        CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        PRFAlgorithm.TLS_PRF_SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA,
                        PRFAlgorithm.TLS_PRF_SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.DTLS12,
                        CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM,
                        PRFAlgorithm.TLS_PRF_SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                        PRFAlgorithm.TLS_PRF_SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT,
                        PRFAlgorithm.TLS_PRF_GOSTR3411));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT,
                        PRFAlgorithm.TLS_PRF_GOSTR3411_2012_256));
        return streamBuilder.build();
    }

    /** Test of getPRFAlgorithm method, of class AlgorithmResolver. */
    @ParameterizedTest
    @MethodSource("provideGetPRFAlgorithmTestVectors")
    public void testGetPRFAlgorithm(
            ProtocolVersion providedProtocolVersion,
            CipherSuite providedCipherSuite,
            PRFAlgorithm expectedPRFAlgorithm) {
        assertSame(
                expectedPRFAlgorithm,
                AlgorithmResolver.getPRFAlgorithm(providedProtocolVersion, providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(
            value = ProtocolVersion.class,
            names = {"SSL2", "SSL3"})
    public void testGetPRFUnsupportedProtocolVersion(ProtocolVersion protocolVersion) {
        assertNull(
                AlgorithmResolver.getPRFAlgorithm(protocolVersion, CipherSuite.TLS_FALLBACK_SCSV));
    }

    /**
     * Provides test vectors of format (providedProtocolVersion, providedCipherSuite,
     * expectedDigestAlgorithm) for {@link #testGetDigestAlgorithm(ProtocolVersion, CipherSuite,
     * DigestAlgorithm)}
     */
    public static Stream<Arguments> provideGetDigestAlgorithmTestVectors() {
        Stream.Builder<Arguments> streamBuilder = Stream.builder();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("GOST")) {
                continue;
            }
            streamBuilder.add(Arguments.of(ProtocolVersion.TLS10, suite, DigestAlgorithm.LEGACY));
            streamBuilder.add(Arguments.of(ProtocolVersion.TLS11, suite, DigestAlgorithm.LEGACY));
            streamBuilder.add(Arguments.of(ProtocolVersion.DTLS10, suite, DigestAlgorithm.LEGACY));
        }
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                        DigestAlgorithm.SHA384));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.DTLS12,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                        DigestAlgorithm.SHA384));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        DigestAlgorithm.SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.DTLS12,
                        CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        DigestAlgorithm.SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        DigestAlgorithm.SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        DigestAlgorithm.SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        DigestAlgorithm.SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA,
                        DigestAlgorithm.SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.DTLS12,
                        CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM,
                        DigestAlgorithm.SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                        DigestAlgorithm.SHA256));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT,
                        DigestAlgorithm.GOSTR3411));
        streamBuilder.add(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT,
                        DigestAlgorithm.GOSTR34112012_256));
        return streamBuilder.build();
    }

    /** Test of getDigestAlgorithm method, of class AlgorithmResolver. */
    @ParameterizedTest
    @MethodSource("provideGetDigestAlgorithmTestVectors")
    public void testGetDigestAlgorithm(
            ProtocolVersion providedProtocolVersion,
            CipherSuite providedCipherSuite,
            DigestAlgorithm expectedDigestAlgorithm) {
        assertSame(
                expectedDigestAlgorithm,
                AlgorithmResolver.getDigestAlgorithm(providedProtocolVersion, providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(
            value = ProtocolVersion.class,
            names = {"SSL2", "SSL3"})
    public void testGetDigestUnsupportedProtocolVersion(ProtocolVersion protocolVersion) {
        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        AlgorithmResolver.getDigestAlgorithm(
                                protocolVersion, CipherSuite.TLS_FALLBACK_SCSV));
    }

    /**
     * Provides test vectors of format (providedCipherSuite, expectedKeyExchangeAlgorithm) for
     * {@link #testGetKeyExchangeAlgorithm(CipherSuite, KeyExchangeAlgorithm)}
     */
    public static Stream<Arguments> provideGetKeyExchangeAlgorithmTestVectors() {
        return Stream.of(
                Arguments.of(
                        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        KeyExchangeAlgorithm.DHE_RSA),
                Arguments.of(
                        CipherSuite.SSL_FORTEZZA_KEA_WITH_NULL_SHA,
                        KeyExchangeAlgorithm.FORTEZZA_KEA),
                Arguments.of(
                        CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384,
                        KeyExchangeAlgorithm.CECPQ1_ECDSA),
                Arguments.of(
                        CipherSuite.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
                        KeyExchangeAlgorithm.DHE_DSS),
                Arguments.of(
                        CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                        KeyExchangeAlgorithm.DHE_DSS),
                Arguments.of(
                        CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
                        KeyExchangeAlgorithm.DHE_PSK),
                Arguments.of(
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                        KeyExchangeAlgorithm.DHE_RSA),
                Arguments.of(
                        CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                        KeyExchangeAlgorithm.DHE_RSA),
                Arguments.of(
                        CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA, KeyExchangeAlgorithm.DH_DSS),
                Arguments.of(
                        CipherSuite.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
                        KeyExchangeAlgorithm.DH_RSA),
                Arguments.of(
                        CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
                        KeyExchangeAlgorithm.DH_ANON),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                        KeyExchangeAlgorithm.ECDHE_ECDSA),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                        KeyExchangeAlgorithm.ECDHE_PSK),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                        KeyExchangeAlgorithm.ECDHE_RSA),
                Arguments.of(
                        CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
                        KeyExchangeAlgorithm.ECDH_ECDSA),
                Arguments.of(
                        CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
                        KeyExchangeAlgorithm.ECDH_RSA),
                Arguments.of(
                        CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
                        KeyExchangeAlgorithm.ECDH_ANON),
                Arguments.of(
                        CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT,
                        KeyExchangeAlgorithm.VKO_GOST01),
                Arguments.of(
                        CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, KeyExchangeAlgorithm.KRB5),
                Arguments.of(CipherSuite.TLS_KRB5_WITH_DES_CBC_SHA, KeyExchangeAlgorithm.KRB5),
                Arguments.of(CipherSuite.TLS_NULL_WITH_NULL_NULL, KeyExchangeAlgorithm.NULL),
                Arguments.of(
                        CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8, KeyExchangeAlgorithm.DHE_PSK),
                Arguments.of(CipherSuite.TLS_PSK_WITH_AES_128_CCM, KeyExchangeAlgorithm.PSK),
                Arguments.of(
                        CipherSuite.TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
                        KeyExchangeAlgorithm.RSA_EXPORT),
                Arguments.of(
                        CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA, KeyExchangeAlgorithm.PSK_RSA),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, KeyExchangeAlgorithm.RSA),
                Arguments.of(
                        CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
                        KeyExchangeAlgorithm.SRP_SHA_DSS),
                Arguments.of(
                        CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
                        KeyExchangeAlgorithm.SRP_SHA_RSA),
                Arguments.of(
                        CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
                        KeyExchangeAlgorithm.SRP_SHA),
                Arguments.of(
                        CipherSuite.UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA,
                        KeyExchangeAlgorithm.ECMQV_ECNRA),
                Arguments.of(
                        CipherSuite.UNOFFICIAL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
                        KeyExchangeAlgorithm.ECDH_ECDSA),
                Arguments.of(
                        CipherSuite.UNOFFICIAL_TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA,
                        KeyExchangeAlgorithm.ECDH_ANON),
                Arguments.of(CipherSuite.TLS_AES_128_GCM_SHA256, null),
                Arguments.of(CipherSuite.TLS_FALLBACK_SCSV, null),
                Arguments.of(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, null));
    }

    /** Test of getKeyExchangeAlgorithm method, of class AlgorithmResolver. */
    @ParameterizedTest
    @MethodSource("provideGetKeyExchangeAlgorithmTestVectors")
    public void testGetKeyExchangeAlgorithm(
            CipherSuite providedCipherSuite, KeyExchangeAlgorithm expectedKeyExchangeAlgorithm) {
        assertSame(
                expectedKeyExchangeAlgorithm,
                AlgorithmResolver.getKeyExchangeAlgorithm(providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(value = CipherSuite.class)
    public void testGetKeyExchangeAlgorithmDoesNotThrow(CipherSuite providedCipherSuite) {
        // Checks that we can retrieve the key exchange algorithm of the provided cipher suite
        // without exceptions
        assertDoesNotThrow(() -> AlgorithmResolver.getKeyExchangeAlgorithm(providedCipherSuite));
    }

    /** Test of getRequiredKeystoreAlgorithms method, of class AlgorithmResolver. */
    @Test
    @Disabled("Not implemented")
    public void testGetRequiredKeystoreAlgorithms() {}

    /**
     * Provides test vectors of format (providedCipherSuite, expectedCipherAlgorithm) for {@link
     * #testGetCipher(CipherSuite, CipherAlgorithm)}
     */
    public static Stream<Arguments> provideGetCipherTestVectors() {
        return Stream.of(
                Arguments.of(CipherSuite.TLS_NULL_WITH_NULL_NULL, CipherAlgorithm.NULL),
                Arguments.of(CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA, CipherAlgorithm.IDEA_128),
                Arguments.of(
                        CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, CipherAlgorithm.RC2_128),
                Arguments.of(CipherSuite.TLS_RSA_WITH_RC4_128_SHA, CipherAlgorithm.RC4_128),
                Arguments.of(
                        CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, CipherAlgorithm.DES_EDE_CBC),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, CipherAlgorithm.AES_128_CBC),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, CipherAlgorithm.AES_256_CBC),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_128_CCM, CipherAlgorithm.AES_128_CCM),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_256_CCM, CipherAlgorithm.AES_256_CCM),
                Arguments.of(
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherAlgorithm.AES_128_GCM),
                Arguments.of(
                        CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384,
                        CipherAlgorithm.AES_256_GCM),
                Arguments.of(
                        CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherAlgorithm.CAMELLIA_128_CBC),
                Arguments.of(
                        CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                        CipherAlgorithm.CAMELLIA_128_GCM),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
                        CipherAlgorithm.CAMELLIA_256_CBC),
                Arguments.of(
                        CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                        CipherAlgorithm.CAMELLIA_256_GCM),
                Arguments.of(CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA, CipherAlgorithm.SEED_CBC),
                Arguments.of(
                        CipherSuite.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
                        CipherAlgorithm.DES40_CBC),
                Arguments.of(CipherSuite.TLS_RSA_WITH_DES_CBC_SHA, CipherAlgorithm.DES_CBC),
                Arguments.of(
                        CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA,
                        CipherAlgorithm.FORTEZZA_CBC),
                Arguments.of(
                        CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256, CipherAlgorithm.ARIA_128_CBC),
                Arguments.of(
                        CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256, CipherAlgorithm.ARIA_128_GCM),
                Arguments.of(
                        CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
                        CipherAlgorithm.ARIA_256_CBC),
                Arguments.of(
                        CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384, CipherAlgorithm.ARIA_256_GCM),
                Arguments.of(
                        CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT,
                        CipherAlgorithm.GOST_28147_CNT),
                Arguments.of(
                        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        CipherAlgorithm.CHACHA20_POLY1305),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        CipherAlgorithm.CHACHA20_POLY1305),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        CipherAlgorithm.CHACHA20_POLY1305),
                Arguments.of(
                        CipherSuite.UNOFFICIAL_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        CipherAlgorithm.UNOFFICIAL_CHACHA20_POLY1305),
                Arguments.of(
                        CipherSuite.UNOFFICIAL_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        CipherAlgorithm.UNOFFICIAL_CHACHA20_POLY1305),
                Arguments.of(
                        CipherSuite.UNOFFICIAL_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        CipherAlgorithm.UNOFFICIAL_CHACHA20_POLY1305));
    }

    /** Test of getCipher method, of class AlgorithmResolver. */
    @ParameterizedTest
    @MethodSource("provideGetCipherTestVectors")
    public void testGetCipher(
            CipherSuite providedCipherSuite, CipherAlgorithm expectedCipherAlgorithm) {
        assertSame(expectedCipherAlgorithm, AlgorithmResolver.getCipher(providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(
            value = CipherSuite.class,
            names = {"TLS_FALLBACK_SCSV", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"})
    public void testUnresolvableCipherUnknown(CipherSuite providedCipherSuite) {
        assertThrows(
                UnsupportedOperationException.class,
                () -> AlgorithmResolver.getCipher(providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(
            value = CipherSuite.class,
            names = {"TLS_FALLBACK_SCSV", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"},
            mode = EnumSource.Mode.EXCLUDE)
    public void testGetCipherDoesNotThrow(CipherSuite providedCipherSuite) {
        // Checks that we can retrieve the cipher of the provided cipher suite without exceptions
        assertDoesNotThrow(() -> AlgorithmResolver.getCipher(providedCipherSuite));
    }

    /**
     * Provides test vectors of format (providedCipherSuite, expectedCipherType) for {@link
     * #testGetCipherType(CipherSuite, CipherType)}
     */
    public static Stream<Arguments> provideGetCipherTypeTestVectors() {
        return Stream.of(
                Arguments.of(CipherSuite.TLS_NULL_WITH_NULL_NULL, CipherType.STREAM),
                Arguments.of(CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_RC4_128_SHA, CipherType.STREAM),
                Arguments.of(CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_128_CCM, CipherType.AEAD),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_256_CCM, CipherType.AEAD),
                Arguments.of(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherType.AEAD),
                Arguments.of(CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384, CipherType.AEAD),
                Arguments.of(CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256, CipherType.AEAD),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384, CipherType.AEAD),
                Arguments.of(CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_DES_CBC_SHA, CipherType.BLOCK),
                Arguments.of(CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256, CipherType.AEAD),
                Arguments.of(CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384, CipherType.BLOCK),
                Arguments.of(CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384, CipherType.AEAD),
                Arguments.of(CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT, CipherType.STREAM),
                Arguments.of(
                        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherType.AEAD),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, CipherType.AEAD),
                Arguments.of(
                        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherType.AEAD));
    }

    /** Test of getCipherType method, of class AlgorithmResolver. */
    @ParameterizedTest
    @MethodSource("provideGetCipherTypeTestVectors")
    public void testGetCipherType(CipherSuite providedCipherSuite, CipherType expectedCipherType) {
        assertSame(expectedCipherType, AlgorithmResolver.getCipherType(providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(
            value = CipherSuite.class,
            names = {"TLS_FALLBACK_SCSV", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"})
    public void testUnresolvableCipherType(CipherSuite providedCipherSuite) {
        assertThrows(
                UnsupportedOperationException.class,
                () -> AlgorithmResolver.getCipher(providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(
            value = CipherSuite.class,
            // These values are known to throw an UnsupportedOperationException and are therefore
            // excluded
            names = {
                "TLS_FALLBACK_SCSV",
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
                "TLS_RSA_WITH_RABBIT_CBC_SHA",
                "GREASE_[0-9]*"
            },
            mode = EnumSource.Mode.MATCH_NONE)
    public void testGetCipherTypeDoesNotThrow(CipherSuite providedCipherSuite) {
        // Checks that we can retrieve the cipher type of the provided cipher suite without
        // exceptions
        assertDoesNotThrow(() -> AlgorithmResolver.getCipherType(providedCipherSuite));
    }

    /**
     * Provides test vectors of format (providedProtocolVersion, providedCipherSuite,
     * expectedMacAlgorithm) for {@link #testGetMacAlgorithm(ProtocolVersion, CipherSuite,
     * MacAlgorithm)}
     */
    public static Stream<Arguments> provideGetMacAlgorithmTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT,
                        MacAlgorithm.IMIT_GOST28147),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_GOSTR341001_WITH_NULL_GOSTR3411,
                        MacAlgorithm.HMAC_GOSTR3411),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_GOSTR341112_256_WITH_NULL_GOSTR3411,
                        MacAlgorithm.HMAC_GOSTR3411_2012_256));
    }

    /** Test of getMacAlgorithm method, of class AlgorithmResolver. */
    @ParameterizedTest
    @MethodSource("provideGetMacAlgorithmTestVectors")
    public void testGetMacAlgorithm(
            ProtocolVersion providedProtocolVersion,
            CipherSuite providedCipherSuite,
            MacAlgorithm expectedMacAlgorithm) {
        assertSame(
                expectedMacAlgorithm,
                AlgorithmResolver.getMacAlgorithm(providedProtocolVersion, providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(
            value = CipherSuite.class,
            names = {"TLS_FALLBACK_SCSV", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"})
    public void testUnresolvableMac(CipherSuite providedCipherSuite) {
        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        AlgorithmResolver.getMacAlgorithm(
                                ProtocolVersion.TLS12, providedCipherSuite));
    }

    @ParameterizedTest
    @EnumSource(
            value = CipherSuite.class,
            // These values are known to throw an UnsupportedOperationException and are therefore
            // excluded
            names = {
                "TLS_FALLBACK_SCSV",
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
                "TLS_RSA_WITH_RABBIT_CBC_SHA",
                "GREASE_[0-9]*"
            },
            mode = EnumSource.Mode.MATCH_NONE)
    public void testGetMacDoesNotThrow(CipherSuite providedCipherSuite) {
        // Checks that we can retrieve the mac algorithm of the provided cipher suite without
        // unexpected exceptions
        assertDoesNotThrow(
                () -> AlgorithmResolver.getMacAlgorithm(ProtocolVersion.SSL3, providedCipherSuite));
        assertDoesNotThrow(
                () ->
                        AlgorithmResolver.getMacAlgorithm(
                                ProtocolVersion.TLS12, providedCipherSuite));
    }

    @Test
    public void testGetHKDFAlgorithm() {
        assertSame(
                HKDFAlgorithm.TLS_HKDF_SHA256,
                AlgorithmResolver.getHKDFAlgorithm(CipherSuite.TLS_AES_128_GCM_SHA256));
    }
}
