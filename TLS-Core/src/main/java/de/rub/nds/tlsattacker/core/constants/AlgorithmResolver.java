/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.HashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Resolves crypto algorithms and their properties from a given cipehr suite
 * (and TLS version).
 */
public class AlgorithmResolver {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Returns a PRF algorithm based on the protocol version and the cipher
     * suite. TLS 1.0 and 1.1 used a legacy PRF based on MD5 and SHA-1. TLS 1.2
     * uses per default SHA256 PRF, but allows for definition of further PRFs in
     * specific cipher suites (the last part of a cipher suite string identifies
     * the PRF).
     *
     * @param protocolVersion
     *            The ProtocolVersion for which the PRFAlgorithm should be
     *            returned
     * @param cipherSuite
     *            The Ciphersuite for which the PRFAlgorithm should be returned
     * @return The selected PRFAlgorithm
     */
    public static PRFAlgorithm getPRFAlgorithm(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        PRFAlgorithm result;
        if (protocolVersion == ProtocolVersion.SSL3 || protocolVersion == ProtocolVersion.SSL2) {
            throw new UnsupportedOperationException("SSL3 and SSL2 PRF currently not supported");
        }
        if (cipherSuite.usesGOSTR3411()) {
            result = PRFAlgorithm.TLS_PRF_GOSTR3411;
        } else if (cipherSuite.usesGOSTR34112012()) {
            result = PRFAlgorithm.TLS_PRF_GOSTR3411_2012_256;
        } else if (protocolVersion == ProtocolVersion.TLS10 || protocolVersion == ProtocolVersion.TLS11
                || protocolVersion == ProtocolVersion.DTLS10) {
            result = PRFAlgorithm.TLS_PRF_LEGACY;
        } else if (cipherSuite.usesSHA384()) {
            result = PRFAlgorithm.TLS_PRF_SHA384;
        } else {
            result = PRFAlgorithm.TLS_PRF_SHA256;
        }
        LOGGER.debug("Using the following PRF Algorithm: {}", result);
        return result;
    }

    /**
     * Returns a digest algorithm based on the protocol version and the cipher
     * suite. The digest algorithm is used to compute a message digest over the
     * handshake messages and to compute valid finished messages. TLS 1.0 and
     * 1.1 used a legacy digest based on MD5 and SHA-1. TLS 1.2 uses per default
     * SHA256 digest algorithm, but allows for definition of further digest
     * algorithms in specific cipher suites (the last part of a cipher suite
     * string identifies the digest).
     *
     * @param protocolVersion
     *            The ProtocolVersion for which the DigestAlgorithm should be
     *            returned
     * @param cipherSuite
     *            The Ciphersuite for which the DigestAlgorithm should be
     *            returned
     * @return The selected DigestAlgorithm
     */
    public static DigestAlgorithm getDigestAlgorithm(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        DigestAlgorithm result;
        if (protocolVersion == ProtocolVersion.SSL3 || protocolVersion == ProtocolVersion.SSL2) {
            throw new UnsupportedOperationException("SSL3 and SSL2 PRF currently not supported");
        }
        if (cipherSuite.usesGOSTR3411()) {
            result = DigestAlgorithm.GOSTR3411;
        } else if (cipherSuite.usesGOSTR34112012()) {
            result = DigestAlgorithm.GOSTR34112012_256;
        } else if (protocolVersion == ProtocolVersion.TLS10 || protocolVersion == ProtocolVersion.TLS11
                || protocolVersion == ProtocolVersion.DTLS10) {
            result = DigestAlgorithm.LEGACY;
        } else if (cipherSuite.usesSHA384()) {
            result = DigestAlgorithm.SHA384;
        } else {
            result = DigestAlgorithm.SHA256;
        }
        LOGGER.debug("Using the following Digest Algorithm: {}", result);
        return result;
    }

    public static KeyExchangeAlgorithm getKeyExchangeAlgorithm(CipherSuite cipherSuite) {
        if (cipherSuite.isTLS13()) {
            return null;
        }
        String cipher = cipherSuite.toString().toUpperCase();
        if (cipher.contains("TLS_RSA_WITH") || cipher.contains("TLS_RSA_EXPORT")) {
            return KeyExchangeAlgorithm.RSA;
        } else if (cipher.contains("TLS_RSA_PSK_")) {
            return KeyExchangeAlgorithm.PSK_RSA;
        } else if (cipher.startsWith("TLS_DH_DSS_")) {
            return KeyExchangeAlgorithm.DH_DSS;
        } else if (cipher.startsWith("TLS_DH_RSA_")) {
            return KeyExchangeAlgorithm.DH_RSA;
        } else if (cipher.startsWith("TLS_DHE_DSS_")) {
            return KeyExchangeAlgorithm.DHE_DSS;
        } else if (cipher.contains("TLS_DHE_RSA_")) {
            return KeyExchangeAlgorithm.DHE_RSA;
        } else if (cipher.contains("TLS_DHE_PSK") || cipher.contains("TLS_PSK_DHE")) {
            return KeyExchangeAlgorithm.DHE_PSK;
        } else if (cipher.startsWith("TLS_DH_ANON_")) {
            return KeyExchangeAlgorithm.DH_ANON;
        } else if (cipher.contains("TLS_ECDHE_RSA")) {
            return KeyExchangeAlgorithm.ECDHE_RSA;
        } else if (cipher.contains("TLS_ECDHE_ECDSA")) {
            return KeyExchangeAlgorithm.ECDHE_ECDSA;
        } else if (cipher.contains("TLS_ECDH_ANON")) {
            return KeyExchangeAlgorithm.ECDH_ANON;
        } else if (cipher.contains("TLS_ECDH_ECDSA")) {
            return KeyExchangeAlgorithm.ECDH_ECDSA;
        } else if (cipher.contains("TLS_ECDH_RSA")) {
            return KeyExchangeAlgorithm.ECDH_RSA;
        } else if (cipher.contains("TLS_ECDHE_PSK")) {
            return KeyExchangeAlgorithm.ECDHE_PSK;
        } else if (cipher.startsWith("TLS_NULL_")) {
            return KeyExchangeAlgorithm.NULL;
        } else if (cipher.startsWith("TLS_KRB5_")) {
            return KeyExchangeAlgorithm.KRB5;
        } else if (cipher.contains("TLS_PSK_")) {
            return KeyExchangeAlgorithm.PSK;
        } else if (cipher.startsWith("TLS_SRP_SHA_RSA")) {
            return KeyExchangeAlgorithm.SRP_SHA_RSA;
        } else if (cipher.startsWith("TLS_SRP_SHA_DSS")) {
            return KeyExchangeAlgorithm.SRP_SHA_DSS;
        } else if (cipher.startsWith("TLS_SRP_SHA")) {
            return KeyExchangeAlgorithm.SRP_SHA;
        } else if (cipher.startsWith("TLS_GOSTR341001_")) {
            return KeyExchangeAlgorithm.VKO_GOST01;
        } else if (cipher.startsWith("TLS_GOSTR341112_")) {
            return KeyExchangeAlgorithm.VKO_GOST12;
        } else if (cipher.startsWith("TLS_CECPQ1_")) {
            return KeyExchangeAlgorithm.CECPQ1_ECDSA;
        } else if (cipher.contains("SSL_FORTEZZA_KEA")) {
            return KeyExchangeAlgorithm.FORTEZZA_KEA;
        } else if (cipher.contains("ECMQV_ECNRA")) {
            return KeyExchangeAlgorithm.ECMQV_ECNRA;
        } else if (cipher.contains("ECMQV_ECDSA")) {
            return KeyExchangeAlgorithm.ECMQV_ECDSA;
        } else if (cipher.contains("ECDH_ECNRA")) {
            return KeyExchangeAlgorithm.ECDH_ECNRA;
        } else if (cipher.contains("ECCPWD")) {
            return KeyExchangeAlgorithm.ECCPWD;
        }
        if (cipherSuite == CipherSuite.TLS_FALLBACK_SCSV
                || cipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            throw new UnsupportedOperationException("The CipherSuite:" + cipherSuite.name()
                    + " does not specify a KeyExchangeAlgorithm");
        }
        throw new UnsupportedOperationException("The key exchange algorithm in " + cipherSuite.toString()
                + " is not supported yet.");
    }

    /**
     * Depending on the provided cipher suite, the server needs to be
     * initialized with proper public key(s). Depending on the cipher suite,
     * there are possibly more than one cipher suites needed.
     *
     * This function returns a list of public key algorithms needed when running
     * a server with a cipher suite.
     *
     * @param cipherSuite
     *            The selected CipherSuite
     * @return The Set of publicKeyAlgorithms
     */
    public static Set<PublicKeyAlgorithm> getRequiredKeystoreAlgorithms(CipherSuite cipherSuite) {
        String cipher = cipherSuite.toString().toUpperCase();
        Set<PublicKeyAlgorithm> result = new HashSet<>();
        if (cipher.contains("RSA")) {
            result.add(PublicKeyAlgorithm.RSA);
        } else if (cipher.contains("ECDSA")) {
            result.add(PublicKeyAlgorithm.EC);
        } else if (cipher.contains("DSS")) {
            result.add(PublicKeyAlgorithm.DH);
        } else if (cipher.contains("GOSTR341112")) {
            result.add(PublicKeyAlgorithm.GOST12);
        } else if (cipher.contains("GOSTR341001")) {
            result.add(PublicKeyAlgorithm.GOST01);
        }

        if (cipher.contains("_ECDH_")) {
            result.add(PublicKeyAlgorithm.EC);
        } else if (cipher.contains("_DH_")) {
            result.add(PublicKeyAlgorithm.DH);
        }
        return result;
    }

    public static CipherAlgorithm getCipher(CipherSuite cipherSuite) {
        String cipher = cipherSuite.toString().toUpperCase();
        if (cipher.contains("NULL")) {
            return CipherAlgorithm.NULL;
        } else if (cipher.contains("IDEA")) {
            return CipherAlgorithm.IDEA_128;
        } else if (cipher.contains("RC2")) {
            return CipherAlgorithm.RC2_128;
        } else if (cipher.contains("RC4")) {
            return CipherAlgorithm.RC4_128;
        } else if (cipher.contains("DES_EDE_CBC")) {
            return CipherAlgorithm.DES_EDE_CBC;
        } else if (cipher.contains("AES_128_CBC")) {
            return CipherAlgorithm.AES_128_CBC;
        } else if (cipher.contains("AES_256_CBC")) {
            return CipherAlgorithm.AES_256_CBC;
        } else if (cipher.contains("AES_128_GCM")) {
            return CipherAlgorithm.AES_128_GCM;
        } else if (cipher.contains("AES_256_GCM")) {
            return CipherAlgorithm.AES_256_GCM;
        } else if (cipher.contains("AES_128_CCM")) {
            return CipherAlgorithm.AES_128_CCM;
        } else if (cipher.contains("AES_256_CCM")) {
            return CipherAlgorithm.AES_256_CCM;
        } else if (cipher.contains("CAMELLIA_128_CBC")) {
            return CipherAlgorithm.CAMELLIA_128_CBC;
        } else if (cipher.contains("CAMELLIA_256_CBC")) {
            return CipherAlgorithm.CAMELLIA_256_CBC;
        } else if (cipher.contains("CAMELLIA_128_GCM")) {
            return CipherAlgorithm.CAMELLIA_128_GCM;
        } else if (cipher.contains("CAMELLIA_256_GCM")) {
            return CipherAlgorithm.CAMELLIA_256_GCM;
        } else if (cipher.contains("SEED_CBC")) {
            return CipherAlgorithm.SEED_CBC;
        } else if (cipher.contains("DES40_CBC")) {
            return CipherAlgorithm.DES40_CBC;
        } else if (cipher.contains("DES_CBC")) {
            return CipherAlgorithm.DES_CBC;
        } else if (cipher.contains("WITH_FORTEZZA_CBC")) {
            return CipherAlgorithm.FORTEZZA_CBC;
        } else if (cipher.contains("ARIA_128_CBC")) {
            return CipherAlgorithm.ARIA_128_CBC;
        } else if (cipher.contains("ARIA_256_CBC")) {
            return CipherAlgorithm.ARIA_256_CBC;
        } else if (cipher.contains("ARIA_128_GCM")) {
            return CipherAlgorithm.ARIA_128_GCM;
        } else if (cipher.contains("ARIA_256_GCM")) {
            return CipherAlgorithm.ARIA_256_GCM;
        } else if (cipher.contains("28147_CNT")) {
            return CipherAlgorithm.GOST_28147_CNT;
        } else if (cipher.contains("CHACHA20_POLY1305")) {
            return CipherAlgorithm.ChaCha20Poly1305;
        }
        if (cipherSuite == CipherSuite.TLS_FALLBACK_SCSV
                || cipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            throw new UnsupportedOperationException("The CipherSuite:" + cipherSuite.name()
                    + " does not specify a Cipher");
        }
        throw new UnsupportedOperationException("The cipher algorithm in " + cipherSuite + " is not supported yet.");
    }

    /**
     * @param cipherSuite
     *            The Ciphersuite for which the BulkCipherAlgorithm should be
     *            returned
     * @return The BulkCipherAlgorithm of the Cipher
     */
    public static BulkCipherAlgorithm getBulkCipherAlgorithm(CipherSuite cipherSuite) {
        return BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite);
    }

    /**
     * @param cipherSuite
     *            The Ciphersuite for which the CipherType should be selected
     * @return The CipherType of the Ciphersuite
     */
    public static CipherType getCipherType(CipherSuite cipherSuite) {
        String cs = cipherSuite.toString().toUpperCase();
        if (cipherSuite.isGCM() || cipherSuite.isCCM() || cipherSuite.isOCB() || cipherSuite.usesStrictExplicitIv()) {
            return CipherType.AEAD;
        } else if (cs.contains("AES") || cs.contains("DES") || cs.contains("IDEA") || cs.contains("WITH_FORTEZZA")
                || cs.contains("CAMELLIA") || cs.contains("WITH_SEED") || cs.contains("WITH_ARIA")
                || cs.contains("RC2")) {
            return CipherType.BLOCK;
        } else if (cs.contains("RC4") || cs.contains("WITH_NULL") || cs.contains("28147_CNT")) {
            return CipherType.STREAM;
        }
        if (cipherSuite == CipherSuite.TLS_FALLBACK_SCSV
                || cipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            throw new UnsupportedOperationException("The CipherSuite:" + cipherSuite.name()
                    + " does not specify a CipherType");
        }
        throw new UnsupportedOperationException("Cipher suite " + cipherSuite + " is not supported yet.");
    }

    public static MacAlgorithm getMacAlgorithm(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        MacAlgorithm result = null;
        if (getCipherType(cipherSuite) == CipherType.AEAD) {
            result = MacAlgorithm.AEAD;
        } else {
            String cipher = cipherSuite.toString();
            if (cipher.contains("MD5")) {
                if (protocolVersion.isSSL()) {
                    result = MacAlgorithm.SSLMAC_MD5;
                } else {
                    result = MacAlgorithm.HMAC_MD5;
                }
            } else if (cipher.endsWith("SHA")) {
                if (protocolVersion.isSSL()) {
                    result = MacAlgorithm.SSLMAC_SHA1;
                } else {
                    result = MacAlgorithm.HMAC_SHA1;
                }
            } else if (cipher.contains("SHA256")) {
                result = MacAlgorithm.HMAC_SHA256;
            } else if (cipher.contains("SHA384")) {
                result = MacAlgorithm.HMAC_SHA384;
            } else if (cipher.contains("SHA512")) {
                result = MacAlgorithm.HMAC_SHA512;
            } else if (cipher.endsWith("NULL")) {
                result = MacAlgorithm.NULL;
            } else if (cipher.endsWith("IMIT")) {
                result = MacAlgorithm.IMIT_GOST28147;
            } else if (cipherSuite.usesGOSTR3411()) {
                result = MacAlgorithm.HMAC_GOSTR3411;
            } else if (cipherSuite.usesGOSTR34112012()) {
                result = MacAlgorithm.HMAC_GOSTR3411_2012_256;
            }
        }
        if (cipherSuite == CipherSuite.TLS_FALLBACK_SCSV
                || cipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            throw new UnsupportedOperationException("The CipherSuite:" + cipherSuite.name()
                    + " does not specify a MAC-Algorithm");
        }
        if (result != null) {
            LOGGER.debug("Using the following Mac Algorithm: {}", result);
            return result;
        } else {
            throw new UnsupportedOperationException("The Mac algorithm for cipher " + cipherSuite
                    + " is not supported yet");
        }
    }

    public static HKDFAlgorithm getHKDFAlgorithm(CipherSuite cipherSuite) {
        HKDFAlgorithm result = null;
        String cipher = cipherSuite.toString();
        if (cipher.endsWith("SHA256")) {
            result = HKDFAlgorithm.TLS_HKDF_SHA256;
        } else if (cipher.endsWith("SHA384")) {
            result = HKDFAlgorithm.TLS_HKDF_SHA384;
        }
        if (result != null) {
            LOGGER.debug("Using the following HKDF Algorithm: {}", result);
            return result;
        } else {
            LOGGER.warn("The HKDF algorithm for cipher suite " + cipherSuite
                    + " is not supported yet or is undefined. Using \"TLS_HKDF_SHA256\"");
            return HKDFAlgorithm.TLS_HKDF_SHA256;
        }
    }

    private AlgorithmResolver() {
    }
}
