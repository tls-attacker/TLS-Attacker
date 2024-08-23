/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.protocol.constants.HashAlgorithm;
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

    @Deprecated // Use cipherSuite.getKeyExchangeAlgorithm instead
    public static KeyExchangeAlgorithm getKeyExchangeAlgorithm(CipherSuite cipherSuite) {
        return cipherSuite.getKeyExchangeAlgorithm();
    }

    /**
     * Returns the certificate types that can be used with the cipher suite
     *
     * @param suite
     * @return
     */
    public static X509PublicKeyType[] getSuiteableLeafCertificateKeyType(CipherSuite suite) {
        KeyExchangeAlgorithm keyExchangeAlgorithm = suite.getKeyExchangeAlgorithm();
        if (keyExchangeAlgorithm == null) {
            return X509PublicKeyType.values();
        }
        switch (keyExchangeAlgorithm) {
            case DHE_RSA:
            case ECDHE_RSA:
            case RSA:
            case RSA_EXPORT:
            case SRP_SHA_RSA:
            case RSA_PSK:
                return new X509PublicKeyType[] { X509PublicKeyType.RSA };
            case DH_RSA:
            case DH_DSS:
                return new X509PublicKeyType[] { X509PublicKeyType.DH };
            case ECDH_ECDSA:
                return new X509PublicKeyType[] {
                        X509PublicKeyType.ECDH_ECDSA, X509PublicKeyType.ECDH_ONLY
                };
            case ECDH_RSA:
                return new X509PublicKeyType[] { X509PublicKeyType.ECDH_ONLY };
            case ECDHE_ECDSA:
            case ECMQV_ECDSA:
            case CECPQ1_ECDSA:
                return new X509PublicKeyType[] { X509PublicKeyType.ECDH_ECDSA };
            case DHE_DSS:
            case SRP_SHA_DSS:
                return new X509PublicKeyType[] { X509PublicKeyType.DSA };
            case VKO_GOST01:
                return new X509PublicKeyType[] { X509PublicKeyType.GOST_R3411_2001 };
            case VKO_GOST12:
                // TODO Not correct
                return new X509PublicKeyType[] { X509PublicKeyType.GOST_R3411_94 };
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
                return new X509PublicKeyType[] { X509PublicKeyType.KEA };
            default:
                throw new UnsupportedOperationException(
                        "Unsupported KeyExchange Algorithm: " + keyExchangeAlgorithm);
        }
    }

    @Deprecated //Use ciphersuite.getCipherAlgorithm() instead
    public static CipherAlgorithm getCipher(CipherSuite cipherSuite) {
        return cipherSuite.getCipherAlgorithm();
    }

    /**
     * @param cipherSuite The Cipher suite for which the BulkCipherAlgorithm should be returned
     * @return The BulkCipherAlgorithm of the Cipher
     */
    @Deprecated // Use BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite); instead
    public static BulkCipherAlgorithm getBulkCipherAlgorithm(CipherSuite cipherSuite) {
        return BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite);
    }

    /**
    * @param cipherSuite The Cipher suite for which the CipherType should be selected
    * @return The CipherType of the Cipher suite. Can be null if its not a real cipher suite
    */
    @Deprecated // Use cipherSuite.getCipherType() instead
    public static CipherType getCipherType(CipherSuite cipherSuite) {
        return cipherSuite.getCipherType();
    }

    public static MacAlgorithm getMacAlgorithm(
            ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        if (cipherSuite.getCipherType() == CipherType.AEAD) {
            return MacAlgorithm.AEAD;
        } else {
            HashAlgorithm hashAlgorithm = cipherSuite.getHashAlgorithm();
            if (hashAlgorithm == HashAlgorithm.MD5) {
                if (protocolVersion.isSSL()) {
                    return MacAlgorithm.SSLMAC_MD5;
                } else {
                    return MacAlgorithm.HMAC_MD5;
                }
            } else if (hashAlgorithm == HashAlgorithm.SHA1) {
                if (protocolVersion.isSSL()) {
                    return MacAlgorithm.SSLMAC_SHA1;
                } else {
                    return MacAlgorithm.HMAC_SHA1;
                }
            } else if (hashAlgorithm == HashAlgorithm.SHA256) {
                return MacAlgorithm.HMAC_SHA256;
            } else if (hashAlgorithm == HashAlgorithm.SHA384) {
                return MacAlgorithm.HMAC_SHA384;
            } else if (hashAlgorithm == HashAlgorithm.SHA512) {
                return MacAlgorithm.HMAC_SHA512;
            } else if (hashAlgorithm == HashAlgorithm.SM3) {
                return MacAlgorithm.HMAC_SM3;
            } else if (hashAlgorithm == HashAlgorithm.NONE) {
                return MacAlgorithm.NULL;
            } else if (hashAlgorithm == HashAlgorithm.GOST_R3411_94) {
                return MacAlgorithm.IMIT_GOST28147;
            } else if (hashAlgorithm == HashAlgorithm.GOST_R3411_12) {
                return MacAlgorithm.HMAC_GOSTR3411_2012_256;
            }
        }
        if (!cipherSuite.isRealCipherSuite()) {
            LOGGER.warn("Trying to retrieve MAC algorithm of a non-real cipher suite: {}", cipherSuite);
        }
        return null;
    }

    public static HKDFAlgorithm getHKDFAlgorithm(CipherSuite cipherSuite) {
        HashAlgorithm hashAlgorithm = cipherSuite.getHashAlgorithm();
        if (hashAlgorithm == HashAlgorithm.SHA256) {
            return HKDFAlgorithm.TLS_HKDF_SHA256;
        } else if (hashAlgorithm == HashAlgorithm.SHA384) {
            return HKDFAlgorithm.TLS_HKDF_SHA384;
        } else if (hashAlgorithm == HashAlgorithm.SM3) {
            return HKDFAlgorithm.TLS_HKDF_SM3;
        }
        LOGGER.warn(
                "The HKDF algorithm for cipher suite "
                        + cipherSuite
                        + " is not supported yet or is undefined. Using \"TLS_HKDF_SHA256\"");
        return HKDFAlgorithm.TLS_HKDF_SHA256;
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
            case RSA_PSK:
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

    private AlgorithmResolver() {
    }
}
