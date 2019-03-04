/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class AlgorithmResolverTest {

    public AlgorithmResolverTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of getPRFAlgorithm method, of class AlgorithmResolver.
     */
    @Test
    public void testGetPRFAlgorithm() {
        // Some protocol versions should always return tls_legacy
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("GOST")) {
                continue;
            }

            assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS10, suite) == PRFAlgorithm.TLS_PRF_LEGACY);
            assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS11, suite) == PRFAlgorithm.TLS_PRF_LEGACY);
            assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.DTLS10, suite) == PRFAlgorithm.TLS_PRF_LEGACY);
        }
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384) == PRFAlgorithm.TLS_PRF_SHA384);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.DTLS12,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384) == PRFAlgorithm.TLS_PRF_SHA384);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.DTLS12,
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.DTLS12, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT) == PRFAlgorithm.TLS_PRF_GOSTR3411);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT) == PRFAlgorithm.TLS_PRF_GOSTR3411_2012_256);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetPRFUnsupportedProtocolVersionSSL2() {
        AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.SSL2, CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetPRFUnsupportedProtocolVersionSSL3() {
        AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.SSL3, CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetDigestUnsupportedProtocolVersionSSL2() {
        AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.SSL2, CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetDigestUnsupportedProtocolVersionSSL3() {
        AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.SSL3, CipherSuite.TLS_FALLBACK_SCSV);
    }

    /**
     * Test of getDigestAlgorithm method, of class AlgorithmResolver.
     */
    @Test
    public void testGetDigestAlgorithm() {
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("GOST")) {
                continue;
            }

            assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS10, suite) == DigestAlgorithm.LEGACY);
            assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS11, suite) == DigestAlgorithm.LEGACY);
            assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.DTLS10, suite) == DigestAlgorithm.LEGACY);
        }
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384) == DigestAlgorithm.SHA384);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.DTLS12,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384) == DigestAlgorithm.SHA384);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.DTLS12,
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.DTLS12,
                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT) == DigestAlgorithm.GOSTR3411);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT) == DigestAlgorithm.GOSTR34112012_256);
    }

    /**
     * Test of getKeyExchangeAlgorithm method, of class AlgorithmResolver.
     */
    @Test
    public void testGetKeyExchangeAlgorithm() {
        // I tried to get one ciphersuite of every type at random
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256) == KeyExchangeAlgorithm.DHE_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.SSL_FORTEZZA_KEA_WITH_NULL_SHA) == KeyExchangeAlgorithm.FORTEZZA_KEA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384) == KeyExchangeAlgorithm.CECPQ1_ECDSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA) == KeyExchangeAlgorithm.DHE_DSS);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA) == KeyExchangeAlgorithm.DHE_DSS);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA) == KeyExchangeAlgorithm.DHE_PSK);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256) == KeyExchangeAlgorithm.DHE_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA) == KeyExchangeAlgorithm.DHE_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA) == KeyExchangeAlgorithm.DH_DSS);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA) == KeyExchangeAlgorithm.DH_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA) == KeyExchangeAlgorithm.DH_ANON);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8) == KeyExchangeAlgorithm.ECDHE_ECDSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384) == KeyExchangeAlgorithm.ECDHE_PSK);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256) == KeyExchangeAlgorithm.ECDHE_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA) == KeyExchangeAlgorithm.ECDH_ECDSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA) == KeyExchangeAlgorithm.ECDH_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA) == KeyExchangeAlgorithm.ECDH_ANON);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT) == KeyExchangeAlgorithm.VKO_GOST01);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5) == KeyExchangeAlgorithm.KRB5);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_KRB5_WITH_DES_CBC_SHA) == KeyExchangeAlgorithm.KRB5);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_NULL_WITH_NULL_NULL) == KeyExchangeAlgorithm.NULL);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8) == KeyExchangeAlgorithm.DHE_PSK);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_PSK_WITH_AES_128_CCM) == KeyExchangeAlgorithm.PSK);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_RSA_EXPORT1024_WITH_RC4_56_MD5) == KeyExchangeAlgorithm.RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA) == KeyExchangeAlgorithm.PSK_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256) == KeyExchangeAlgorithm.RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA) == KeyExchangeAlgorithm.SRP_SHA_DSS);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA) == KeyExchangeAlgorithm.SRP_SHA_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA) == KeyExchangeAlgorithm.SRP_SHA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA) == KeyExchangeAlgorithm.ECMQV_ECNRA);
        assertTrue(AlgorithmResolver
                .getKeyExchangeAlgorithm(CipherSuite.UNOFFICIAL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA) == KeyExchangeAlgorithm.ECDH_ECDSA);
        assertTrue(AlgorithmResolver
                .getKeyExchangeAlgorithm(CipherSuite.UNOFFICIAL_TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA) == KeyExchangeAlgorithm.ECDH_ANON);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_AES_128_GCM_SHA256) == null);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableKeyExchangeUnknown() {
        AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableKeyExchangeReno() {
        AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableKeyExchangeFallback() {
        AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test
    public void testAllCipherSuitesGetKeyExchange() {
        // Checks that we can retrieve all ciphersuites key exchange algorithms
        // and
        // that none throws an unsupported operation exception
        // Only UnsupportedOperationException are allowed here
        for (CipherSuite suite : CipherSuite.values()) {
            try {
                AlgorithmResolver.getKeyExchangeAlgorithm(suite);
            } catch (UnsupportedOperationException E) {
            }
        }
    }

    /**
     * Test of getRequiredKeystoreAlgorithms method, of class AlgorithmResolver.
     */
    @Test
    public void testGetRequiredKeystoreAlgorithms() {
    }

    /**
     * Test of getCipher method, of class AlgorithmResolver.
     */
    @Test
    public void testGetCipher() {
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_NULL_WITH_NULL_NULL) == CipherAlgorithm.NULL);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA) == CipherAlgorithm.IDEA_128);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5) == CipherAlgorithm.RC2_128);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_RC4_128_SHA) == CipherAlgorithm.RC4_128);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA) == CipherAlgorithm.DES_EDE_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA) == CipherAlgorithm.AES_128_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA) == CipherAlgorithm.AES_256_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_AES_128_CCM) == CipherAlgorithm.AES_128_CCM);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_AES_256_CCM) == CipherAlgorithm.AES_256_CCM);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256) == CipherAlgorithm.AES_128_GCM);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384) == CipherAlgorithm.AES_256_GCM);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256) == CipherAlgorithm.CAMELLIA_128_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256) == CipherAlgorithm.CAMELLIA_128_GCM);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384) == CipherAlgorithm.CAMELLIA_256_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384) == CipherAlgorithm.CAMELLIA_256_GCM);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA) == CipherAlgorithm.SEED_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA) == CipherAlgorithm.DES40_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_DES_CBC_SHA) == CipherAlgorithm.DES_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA) == CipherAlgorithm.FORTEZZA_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256) == CipherAlgorithm.ARIA_128_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256) == CipherAlgorithm.ARIA_128_GCM);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384) == CipherAlgorithm.ARIA_256_CBC);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384) == CipherAlgorithm.ARIA_256_GCM);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT) == CipherAlgorithm.GOST_28147_CNT);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256) == CipherAlgorithm.ChaCha20Poly1305);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == CipherAlgorithm.ChaCha20Poly1305);
        assertTrue(AlgorithmResolver.getCipher(CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) == CipherAlgorithm.ChaCha20Poly1305);
    }

    @Test
    public void testGetAllCipher() {
        // Test that we can retrieve a Cipher for every Ciphersuite
        for (CipherSuite suite : CipherSuite.values()) {
            try {
                AlgorithmResolver.getCipher(suite);
            } catch (UnsupportedOperationException E) {
            }
        }
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableCipherUnknown() {
        AlgorithmResolver.getCipher(CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableCipherReno() {
        AlgorithmResolver.getCipher(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableCipherFallback() {
        AlgorithmResolver.getCipher(CipherSuite.TLS_FALLBACK_SCSV);
    }

    // Test that we can receive a cipher type for every ciphersuite
    @Test
    public void testGetAllCipherTypes() {
        // Test that we can retrieve a Cipher for every Ciphersuite
        for (CipherSuite suite : CipherSuite.values()) {
            try {
                AlgorithmResolver.getCipherType(suite);
            } catch (UnsupportedOperationException E) {
            }
        }
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableCipherTypeUnknown() {
        AlgorithmResolver.getCipherType(CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableCipherTypeReno() {
        AlgorithmResolver.getCipherType(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableCipherTypeFallback() {
        AlgorithmResolver.getCipherType(CipherSuite.TLS_FALLBACK_SCSV);
    }

    /**
     * Test of getCipherType method, of class AlgorithmResolver.
     */
    @Test
    public void testGetCipherType() {
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_NULL_WITH_NULL_NULL) == CipherType.STREAM);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_RC4_128_SHA) == CipherType.STREAM);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_AES_128_CCM) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_AES_256_CCM) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_DES_CBC_SHA) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384) == CipherType.BLOCK);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT) == CipherType.STREAM);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == CipherType.AEAD);
        assertTrue(AlgorithmResolver.getCipherType(CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) == CipherType.AEAD);
    }

    /**
     * Test of getMacAlgorithm method, of class AlgorithmResolver.
     */
    @Test
    public void testGetMacAlgorithm() {
        assertEquals(AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT), MacAlgorithm.IMIT_GOST28147);
        assertEquals(AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_GOSTR341001_WITH_NULL_GOSTR3411), MacAlgorithm.HMAC_GOSTR3411);
        assertEquals(AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12,
                CipherSuite.TLS_GOSTR341112_256_WITH_NULL_GOSTR3411), MacAlgorithm.HMAC_GOSTR3411_2012_256);
    }

    // Test get Mac algorithm for all ciphersuites
    @Test
    public void getAllMacAlgorithms() {
        for (CipherSuite suite : CipherSuite.values()) {
            try {
                AlgorithmResolver.getMacAlgorithm(ProtocolVersion.SSL3, suite);
                AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12, suite);
            } catch (UnsupportedOperationException E) {

            }
        }
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableMACUnknown() {
        AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableMACReno() {
        AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnresolvableMACFallback() {
        AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test
    public void testGetHKDFAlgorithm() {
        CipherSuite cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        HKDFAlgorithm result = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        HKDFAlgorithm result_correct = HKDFAlgorithm.TLS_HKDF_SHA256;
        assertTrue(result == result_correct);
    }
}
