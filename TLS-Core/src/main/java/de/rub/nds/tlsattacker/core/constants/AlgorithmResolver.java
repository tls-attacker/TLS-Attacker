/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Resolves crypto algorithms and their properties from a given cipher suite (and TLS version). */
public class AlgorithmResolver {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Returns a PRF algorithm based on the protocol version and the cipher suite. TLS 1.0 and 1.1
     * used a legacy PRF based on MD5 and SHA-1. TLS 1.2 uses per default SHA256 PRF, but allows for
     * definition of further PRFs in specific cipher suites (the last part of a cipher suite string
     * identifies the PRF).
     *
     * @param protocolVersion The ProtocolVersion for which the PRFAlgorithm should be returned
     * @param cipherSuite The Cipher suite for which the PRFAlgorithm should be returned
     * @return The selected PRFAlgorithm
     */
    public static PRFAlgorithm getPRFAlgorithm(
            ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        PRFAlgorithm result;
        if (protocolVersion == ProtocolVersion.SSL3 || protocolVersion == ProtocolVersion.SSL2) {
            return null;
        }
        if (cipherSuite.usesGOSTR3411()) {
            result = PRFAlgorithm.TLS_PRF_GOSTR3411;
        } else if (cipherSuite.usesGOSTR34112012()) {
            result = PRFAlgorithm.TLS_PRF_GOSTR3411_2012_256;
        } else if (protocolVersion == ProtocolVersion.TLS10
                || protocolVersion == ProtocolVersion.TLS11
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
     * Returns a digest algorithm based on the protocol version and the cipher suite. The digest
     * algorithm is used to compute a message digest over the handshake messages and to compute
     * valid finished messages. TLS 1.0 and 1.1 used a legacy digest based on MD5 and SHA-1. TLS 1.2
     * uses per default SHA256 digest algorithm, but allows for definition of further digest
     * algorithms in specific cipher suites (the last part of a cipher suite string identifies the
     * digest).
     *
     * @param protocolVersion The ProtocolVersion for which the DigestAlgorithm should be returned
     * @param cipherSuite The Cipher suite for which the DigestAlgorithm should be returned
     * @return The selected DigestAlgorithm
     */
    public static DigestAlgorithm getDigestAlgorithm(
            ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        DigestAlgorithm result;
        if (protocolVersion == ProtocolVersion.SSL3 || protocolVersion == ProtocolVersion.SSL2) {
            throw new UnsupportedOperationException("SSL3 and SSL2 PRF currently not supported");
        }
        if (cipherSuite.usesGOSTR3411()) {
            result = DigestAlgorithm.GOSTR3411;
        } else if (cipherSuite.usesGOSTR34112012()) {
            result = DigestAlgorithm.GOSTR34112012_256;
        } else if (protocolVersion == ProtocolVersion.TLS10
                || protocolVersion == ProtocolVersion.TLS11
                || protocolVersion == ProtocolVersion.DTLS10) {
            result = DigestAlgorithm.LEGACY;
        } else if (cipherSuite.isSM()) {
            result = DigestAlgorithm.SM3;
        } else if (cipherSuite.usesSHA384()) {
            result = DigestAlgorithm.SHA384;
        } else {
            result = DigestAlgorithm.SHA256;
        }
        LOGGER.debug("Using the following Digest Algorithm: {}", result);
        return result;
    }

    public static KeyExchangeAlgorithm getKeyExchangeAlgorithm(CipherSuite cipherSuite) {
        if (cipherSuite.isTLS13()
                || cipherSuite == CipherSuite.TLS_FALLBACK_SCSV
                || cipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            return null;
        }
        String cipher = cipherSuite.toString().toUpperCase();
        if (cipher.contains("TLS_RSA_WITH")) {
            return KeyExchangeAlgorithm.RSA;
        } else if (cipher.contains("TLS_RSA_EXPORT")) {
            return KeyExchangeAlgorithm.RSA_EXPORT;
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
        } else if (cipher.contains("TLS_GOSTR341094")) {
            return KeyExchangeAlgorithm.VKO_GOST01;
        }
        LOGGER.warn(
                "The key exchange algorithm in "
                        + cipherSuite.toString()
                        + " is not supported yet or does not define a key exchange algorithm.");
        return null;
    }

    /**
     * Returns the certificate types that can be used with the cipher suite
     *
     * @param suite
     * @return
     */
    public static X509PublicKeyType[] getSuiteableLeafCertificateKeyType(CipherSuite suite) {
        KeyExchangeAlgorithm keyExchangeAlgorithm = getKeyExchangeAlgorithm(suite);
        if (keyExchangeAlgorithm == null) {
            return X509PublicKeyType.values();
        }
        switch (keyExchangeAlgorithm) {
            case DHE_RSA:
            case ECDHE_RSA:
            case RSA:
            case RSA_EXPORT:
            case SRP_SHA_RSA:
            case PSK_RSA:
                return new X509PublicKeyType[] {X509PublicKeyType.RSA};
            case DH_RSA:
            case DH_DSS:
                return new X509PublicKeyType[] {X509PublicKeyType.DH};
            case ECDH_ECDSA:
                return new X509PublicKeyType[] {X509PublicKeyType.ECDH_ECDSA};
            case ECDH_RSA:
                return new X509PublicKeyType[] {X509PublicKeyType.ECDH_ECDSA};
            case ECDHE_ECDSA:
            case ECMQV_ECDSA:
            case CECPQ1_ECDSA:
                return new X509PublicKeyType[] {X509PublicKeyType.ECDH_ECDSA};
            case DHE_DSS:
            case SRP_SHA_DSS:
                return new X509PublicKeyType[] {X509PublicKeyType.DSA};
            case VKO_GOST01:
                return new X509PublicKeyType[] {X509PublicKeyType.GOST_R3411_2001};
            case VKO_GOST12:
                // TODO Not correct
                return new X509PublicKeyType[] {X509PublicKeyType.GOST_R3411_94};
            case DHE_PSK:
            case DH_ANON:
            case ECCPWD:
            case ECDHE_PSK:
            case ECDH_ANON:
            case NULL:
            case PSK:
            case SRP_SHA:
            case KRB5:
                return null;
            case ECDH_ECNRA:
            case ECMQV_ECNRA:
                throw new UnsupportedOperationException("Not Implemented");
            case FORTEZZA_KEA:
                return new X509PublicKeyType[] {X509PublicKeyType.KEA};
            default:
                throw new UnsupportedOperationException(
                        "Unsupported KeyExchange Algorithm: " + keyExchangeAlgorithm);
        }
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
        } else if (cipher.contains("SM4_GCM")) {
            return CipherAlgorithm.SM4_GCM;
        } else if (cipher.contains("SM4_CCM")) {
            return CipherAlgorithm.SM4_CCM;
        } else if (cipher.contains("CHACHA20_POLY1305")) {
            if (cipher.contains("UNOFFICIAL")) {
                return CipherAlgorithm.UNOFFICIAL_CHACHA20_POLY1305;
            } else {
                return CipherAlgorithm.CHACHA20_POLY1305;
            }
        }
        if (cipherSuite == CipherSuite.TLS_FALLBACK_SCSV
                || cipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            throw new UnsupportedOperationException(
                    "The CipherSuite:"
                            + cipherSuite.name()
                            + " does not specify a CipherAlgorithm");
        }

        LOGGER.warn(
                "The cipher algorithm in "
                        + cipherSuite
                        + " is not supported yet. Falling back to NULL.");
        return CipherAlgorithm.NULL;
    }

    /**
     * @param cipherSuite The Cipher suite for which the BulkCipherAlgorithm should be returned
     * @return The BulkCipherAlgorithm of the Cipher
     */
    public static BulkCipherAlgorithm getBulkCipherAlgorithm(CipherSuite cipherSuite) {
        return BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite);
    }

    /**
     * @param cipherSuite The Cipher suite for which the CipherType should be selected
     * @return The CipherType of the Cipher suite
     */
    public static CipherType getCipherType(CipherSuite cipherSuite) {
        String cs = cipherSuite.toString().toUpperCase();
        if (cipherSuite.isGCM()
                || cipherSuite.isCCM()
                || cipherSuite.isOCB()
                || cipherSuite.usesStrictExplicitIv()) {
            return CipherType.AEAD;
        } else if (cs.contains("AES")
                || cs.contains("DES")
                || cs.contains("IDEA")
                || cs.contains("WITH_FORTEZZA")
                || cs.contains("CAMELLIA")
                || cs.contains("WITH_SEED")
                || cs.contains("WITH_ARIA")
                || cs.contains("RC2")) {
            return CipherType.BLOCK;
        } else if (cs.contains("RC4") || cs.contains("WITH_NULL") || cs.contains("28147_CNT")) {
            return CipherType.STREAM;
        }
        if (cipherSuite == CipherSuite.TLS_FALLBACK_SCSV
                || cipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            throw new UnsupportedOperationException(
                    "The CipherSuite:" + cipherSuite.name() + " does not specify a CipherType");
        }
        throw new UnsupportedOperationException(
                "Cipher suite " + cipherSuite + " is not supported yet.");
    }

    public static MacAlgorithm getMacAlgorithm(
            ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
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
            } else if (cipher.contains("SM3")) {
                result = MacAlgorithm.HMAC_SM3;
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
            throw new UnsupportedOperationException(
                    "The CipherSuite:" + cipherSuite.name() + " does not specify a MAC-Algorithm");
        }
        if (result != null) {
            LOGGER.debug("Using the following Mac Algorithm: {}", result);
            return result;
        } else {
            throw new UnsupportedOperationException(
                    "The Mac algorithm for cipher " + cipherSuite + " is not supported yet");
        }
    }

    public static HKDFAlgorithm getHKDFAlgorithm(CipherSuite cipherSuite) {
        HKDFAlgorithm result = null;
        String cipher = cipherSuite.toString();
        if (cipher.endsWith("SHA256")) {
            result = HKDFAlgorithm.TLS_HKDF_SHA256;
        } else if (cipher.endsWith("SHA384")) {
            result = HKDFAlgorithm.TLS_HKDF_SHA384;
        } else if (cipher.endsWith("SM3")) {
            result = HKDFAlgorithm.TLS_HKDF_SM3;
        }
        if (result != null) {
            LOGGER.debug("Using the following HKDF Algorithm: {}", result);
            return result;
        } else {
            LOGGER.warn(
                    "The HKDF algorithm for cipher suite "
                            + cipherSuite
                            + " is not supported yet or is undefined. Using \"TLS_HKDF_SHA256\"");
            return HKDFAlgorithm.TLS_HKDF_SHA256;
        }
    }

    /**
     * Returns the signature algorithm required for the authentication type specified by cipher
     * suite.
     *
     * @param cipherSuite The Cipher suite for which the signature algorithm should be returned
     * @return The required signature algorithm.
     */
    public static SignatureAlgorithm getRequiredSignatureAlgorithm(CipherSuite cipherSuite) {
        KeyExchangeAlgorithm keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);
        if (keyExchangeAlgorithm == null) {
            return null;
        }
        switch (keyExchangeAlgorithm) {
            case DH_RSA:
            case DHE_RSA:
            case ECDH_RSA:
            case ECDHE_RSA:
            case RSA:
            case RSA_EXPORT:
            case SRP_SHA_RSA:
            case PSK_RSA:
                return SignatureAlgorithm.RSA_PKCS1;
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECMQV_ECDSA:
            case CECPQ1_ECDSA:
                return SignatureAlgorithm.ECDSA;
            case DHE_DSS:
            case DH_DSS:
            case SRP_SHA_DSS:
                return SignatureAlgorithm.DSA;
            case VKO_GOST01:
                return SignatureAlgorithm.GOSTR34102001;
            case VKO_GOST12:
                return SignatureAlgorithm.GOSTR34102012_256;
            default:
                return null;
        }
    }

    private AlgorithmResolver() {}
}
