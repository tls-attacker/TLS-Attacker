/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
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
        //Some protocol versions should always return tls_legacy
        for (CipherSuite suite : CipherSuite.values()) {
            assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS10, suite) == PRFAlgorithm.TLS_PRF_LEGACY);
            assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS11, suite) == PRFAlgorithm.TLS_PRF_LEGACY);
            assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.DTLS10, suite) == PRFAlgorithm.TLS_PRF_LEGACY);
        }
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384) == PRFAlgorithm.TLS_PRF_SHA384);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.DTLS12, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384) == PRFAlgorithm.TLS_PRF_SHA384);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.DTLS12, CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12, CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.DTLS12, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM) == PRFAlgorithm.TLS_PRF_SHA256);
        assertTrue(AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5) == PRFAlgorithm.TLS_PRF_SHA256);

    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetPRFUnsupportedProtocolVersionSSL2() {
        AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.SSL2, CipherSuite.TLS_UNKNOWN_CIPHER);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetDigestUnsupportedProtocolVersionSSL3() {
        AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.SSL2, CipherSuite.TLS_UNKNOWN_CIPHER);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetDigestUnsupportedProtocolVersionSSL2() {
        AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.SSL2, CipherSuite.TLS_UNKNOWN_CIPHER);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetPRFUnsupportedProtocolVersionSSL3() {
        AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.SSL2, CipherSuite.TLS_UNKNOWN_CIPHER);
    }

    /**
     * Test of getDigestAlgorithm method, of class AlgorithmResolver.
     */
    @Test
    public void testGetDigestAlgorithm() {
        for (CipherSuite suite : CipherSuite.values()) {
            assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS10, suite) == DigestAlgorithm.LEGACY);
            assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS11, suite) == DigestAlgorithm.LEGACY);
            assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.DTLS10, suite) == DigestAlgorithm.LEGACY);
        }
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384) == DigestAlgorithm.SHA384);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.DTLS12, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384) == DigestAlgorithm.SHA384);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.DTLS12, CipherSuite.TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12, CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.DTLS12, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM) == DigestAlgorithm.SHA256);
        assertTrue(AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12, CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5) == DigestAlgorithm.SHA256);

    }

    /**
     * Test of getKeyExchangeAlgorithm method, of class AlgorithmResolver.
     */
    @Test
    public void testGetKeyExchangeAlgorithm() {
        //I tried to get one ciphersuite of every type at random
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.RFC_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256) == KeyExchangeAlgorithm.DHE_RSA);
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
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT) == KeyExchangeAlgorithm.GOSTR341001);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5) == KeyExchangeAlgorithm.KRB5);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_KRB5_WITH_DES_CBC_SHA) == KeyExchangeAlgorithm.KRB5);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_NULL_WITH_NULL_NULL) == KeyExchangeAlgorithm.NULL);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8) == KeyExchangeAlgorithm.DHE_PSK);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_PSK_WITH_AES_128_CCM) == KeyExchangeAlgorithm.PSK);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_RSA_EXPORT1024_WITH_RC4_56_MD5) == KeyExchangeAlgorithm.RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA) == KeyExchangeAlgorithm.RSA_PSK);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256) == KeyExchangeAlgorithm.RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA) == KeyExchangeAlgorithm.SRP_SHA_DSS);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA) == KeyExchangeAlgorithm.SRP_SHA_RSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA) == KeyExchangeAlgorithm.SRP_SHA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA) == KeyExchangeAlgorithm.ECMQV_ECNRA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.UNOFFICIAL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA) == KeyExchangeAlgorithm.ECDH_ECDSA);
        assertTrue(AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.UNOFFICIAL_TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA) == KeyExchangeAlgorithm.ECDH_ANON);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUnresolvableKeyExchangeUnknown() {
        AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_UNKNOWN_CIPHER);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUnresolvableKeyExchangeReno() {
        AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUnresolvableKeyExchangeFallback() {
        AlgorithmResolver.getKeyExchangeAlgorithm(CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test
    public void testAllCipherSuitesGetKeyExchange() {
        //Checks that we can retrieve all ciphersuites key exchange algorithms and 
        //that none throws an unsupported operation exception
        //Only IllegalArgmumentExceptions are allowed here
        for (CipherSuite suite : CipherSuite.values()) {
            try {
                AlgorithmResolver.getKeyExchangeAlgorithm(suite);
            } catch (IllegalArgumentException E) {
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
    }

    /**
     * Test of getCipherType method, of class AlgorithmResolver.
     */
    @Test
    public void testGetCipherType() {
    }

    /**
     * Test of getMacAlgorithm method, of class AlgorithmResolver.
     */
    @Test
    public void testGetMacAlgorithm() {
    }

}
