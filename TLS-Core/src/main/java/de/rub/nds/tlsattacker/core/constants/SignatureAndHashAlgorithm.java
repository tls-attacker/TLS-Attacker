/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum SignatureAndHashAlgorithm {
    ANONYMOUS_NONE(0x0000, null, null),
    ANONYMOUS_MD5(0x0100, null, HashAlgorithm.MD5),
    ANONYMOUS_SHA1(0x0200, null, HashAlgorithm.SHA1),
    ANONYMOUS_SHA224(0x0300, null, HashAlgorithm.SHA224),
    ANONYMOUS_SHA256(0x0400, null, HashAlgorithm.SHA256),
    ANONYMOUS_SHA384(0x0500, null, HashAlgorithm.SHA384),
    ANONYMOUS_SHA512(0x0600, null, HashAlgorithm.SHA512),
    RSA_NONE(0x0001, SignatureAlgorithm.RSA_PKCS1, null),
    RSA_MD5(0x0101, SignatureAlgorithm.RSA_PKCS1, HashAlgorithm.MD5),
    RSA_SHA1(0x0201, SignatureAlgorithm.RSA_PKCS1, HashAlgorithm.SHA1),
    RSA_SHA224(0x0301, SignatureAlgorithm.RSA_PKCS1, HashAlgorithm.SHA224),
    RSA_SHA256(0x0401, SignatureAlgorithm.RSA_PKCS1, HashAlgorithm.SHA256),
    RSA_SHA384(0x0501, SignatureAlgorithm.RSA_PKCS1, HashAlgorithm.SHA384),
    RSA_SHA512(0x0601, SignatureAlgorithm.RSA_PKCS1, HashAlgorithm.SHA512),
    DSA_NONE(0x0002, SignatureAlgorithm.DSA, null),
    DSA_MD5(0x0102, SignatureAlgorithm.DSA, HashAlgorithm.MD5),
    DSA_SHA1(0x0202, SignatureAlgorithm.DSA, HashAlgorithm.SHA1),
    DSA_SHA224(0x0302, SignatureAlgorithm.DSA, HashAlgorithm.SHA224),
    DSA_SHA256(0x0402, SignatureAlgorithm.DSA, HashAlgorithm.SHA256),
    DSA_SHA384(0x0502, SignatureAlgorithm.DSA, HashAlgorithm.SHA384),
    DSA_SHA512(0x0602, SignatureAlgorithm.DSA, HashAlgorithm.SHA512),
    ECDSA_NONE(0x0003, SignatureAlgorithm.ECDSA, null),
    ECDSA_MD5(0x0103, SignatureAlgorithm.ECDSA, HashAlgorithm.MD5),
    ECDSA_SHA1(0x0203, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA1),
    ECDSA_SHA224(0x0303, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA224),
    ECDSA_SHA256(0x0403, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256),
    ECDSA_SHA384(0x0503, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA384),
    ECDSA_SHA512(0x0603, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA512),
    SM2_SM3(0x0708, SignatureAlgorithm.ECDSA, HashAlgorithm.SM3),
    ED25519(0x0807, SignatureAlgorithm.ED25519, HashAlgorithm.SHA256),
    ED448(0x0808, SignatureAlgorithm.ED448, HashAlgorithm.SHA3_256),
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RSA_PSS_RSAE_SHA256(0x0804, SignatureAlgorithm.RSA_SSA_PSS, HashAlgorithm.SHA256),
    RSA_PSS_RSAE_SHA384(0x0805, SignatureAlgorithm.RSA_SSA_PSS, HashAlgorithm.SHA384),
    RSA_PSS_RSAE_SHA512(0x0806, SignatureAlgorithm.RSA_SSA_PSS, HashAlgorithm.SHA512),
    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RSA_PSS_PSS_SHA256(0x0809, SignatureAlgorithm.RSA_SSA_PSS, HashAlgorithm.SHA256),
    RSA_PSS_PSS_SHA384(0x080a, SignatureAlgorithm.RSA_SSA_PSS, HashAlgorithm.SHA384),
    RSA_PSS_PSS_SHA512(0x080b, SignatureAlgorithm.RSA_SSA_PSS, HashAlgorithm.SHA512),
    GOSTR34102001_GOSTR3411(
            0xEDED, SignatureAlgorithm.GOSTR34102001, null), // TODO this is probably not correct
    GOSTR34102012_256_GOSTR34112012_256(
            0xEEEE,
            SignatureAlgorithm.GOSTR34102012_256,
            null), // TODO this is probably not correct
    GOSTR34102012_512_GOSTR34112012_512(
            0xEFEF, SignatureAlgorithm.GOSTR34102001, null), // TODO this is probably not correct

    ECDSA_BRAINPOOL_P256R1_TLS13_SHA256(0x081A, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256),
    ECDSA_BRAINPOOL_P384R1_TLS13_SHA384(0x081B, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA384),
    ECDSA_BRAINPOOL_P512R1_TLS13_SHA512(0x081C, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA512),

    // GREASE constants
    GREASE_00(0x0A0A, null, null),
    GREASE_01(0x1A1A, null, null),
    GREASE_02(0x2A2A, null, null),
    GREASE_03(0x3A3A, null, null),
    GREASE_04(0x4A4A, null, null),
    GREASE_05(0x5A5A, null, null),
    GREASE_06(0x6A6A, null, null),
    GREASE_07(0x7A7A, null, null),
    GREASE_08(0x8A8A, null, null),
    GREASE_09(0x9A9A, null, null),
    GREASE_10(0xAAAA, null, null),
    GREASE_11(0xBABA, null, null),
    GREASE_12(0xCACA, null, null),
    GREASE_13(0xDADA, null, null),
    GREASE_14(0xEAEA, null, null),
    GREASE_15(0xFAFA, null, null);

    private static final Logger LOGGER = LogManager.getLogger();

    public static List<? extends SignatureAndHashAlgorithm> getImplemented() {
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(DSA_SHA1);
        algoList.add(DSA_SHA224);
        algoList.add(DSA_SHA256);
        algoList.add(DSA_SHA384);
        algoList.add(DSA_SHA512);
        algoList.add(RSA_MD5);
        algoList.add(RSA_SHA1);
        algoList.add(RSA_SHA224);
        algoList.add(RSA_SHA256);
        algoList.add(RSA_SHA384);
        algoList.add(RSA_SHA512);
        algoList.add(ECDSA_SHA1);
        algoList.add(ECDSA_SHA224);
        algoList.add(ECDSA_SHA256);
        algoList.add(ECDSA_SHA384);
        algoList.add(ECDSA_SHA512);
        algoList.add(RSA_PSS_RSAE_SHA256);
        algoList.add(RSA_PSS_RSAE_SHA384);
        algoList.add(RSA_PSS_RSAE_SHA512);
        algoList.add(RSA_PSS_PSS_SHA256);
        algoList.add(RSA_PSS_PSS_SHA384);
        algoList.add(RSA_PSS_PSS_SHA512);
        /**
         * Deactivated since the Protocol-Attacker rework, as Protocol-Attacker does not support
         * them.
         */
        // algoList.add(GOSTR34102001_GOSTR3411);
        // algoList.add(GOSTR34102012_256_GOSTR34112012_256);
        // algoList.add(GOSTR34102012_512_GOSTR34112012_512);
        algoList.add(SM2_SM3);
        return algoList;
    }

    public static List<SignatureAndHashAlgorithm> getTls13SignatureAndHashAlgorithms() {
        List<SignatureAndHashAlgorithm> algos = new LinkedList<>();
        algos.add(SignatureAndHashAlgorithm.RSA_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_SHA512);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        algos.add(SignatureAndHashAlgorithm.ED448);
        algos.add(SignatureAndHashAlgorithm.ED25519);
        algos.add(SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P256R1_TLS13_SHA256);
        algos.add(SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P384R1_TLS13_SHA384);
        algos.add(SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P512R1_TLS13_SHA512);
        algos.add(SignatureAndHashAlgorithm.SM2_SM3);
        return algos;
    }

    public static List<SignatureAndHashAlgorithm> getImplementedTls13SignatureAndHashAlgorithms() {
        return getTls13SignatureAndHashAlgorithms().stream()
                .filter(algorithm -> SignatureAndHashAlgorithm.getImplemented().contains(algorithm))
                .collect(Collectors.toList());
    }

    private int value;

    private HashAlgorithm hashAlgorithm;

    private SignatureAlgorithm signatureAlgorithm;

    private static final Map<Integer, SignatureAndHashAlgorithm> MAP;

    private SignatureAndHashAlgorithm(
            int value, SignatureAlgorithm signatureAlgorithm, HashAlgorithm hashAlgorithm) {
        this.value = value;
        this.hashAlgorithm = hashAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    static {
        MAP = new HashMap<>();
        for (SignatureAndHashAlgorithm c : SignatureAndHashAlgorithm.values()) {
            MAP.put(c.value, c);
        }
    }

    private static int valueToInt(byte[] value) {
        if (value.length >= 2) {
            return (value[0] & 0xff) << Bits.IN_A_BYTE | (value[1] & 0xff);
        } else if (value.length == 1) {
            return value[0];
        } else {
            return 0;
        }
    }

    public static List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms(
            byte[] signatureAndHashBytes) {
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        if (signatureAndHashBytes.length % HandshakeByteLength.SIGNATURE_HASH_ALGORITHM != 0) {
            throw new ParserException("Error while parsing signatureAndHashAlgorithm Bytes");
        }
        ByteArrayInputStream algorithmsStream = new ByteArrayInputStream(signatureAndHashBytes);
        byte[] algoBytes = new byte[HandshakeByteLength.SIGNATURE_HASH_ALGORITHM];
        while (algorithmsStream.read(algoBytes, 0, HandshakeByteLength.SIGNATURE_HASH_ALGORITHM)
                != -1) {
            SignatureAndHashAlgorithm algo =
                    SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algoBytes);
            if (algo == null) {
                LOGGER.warn("Unknown SignatureAndHashAlgorithm: {}", algoBytes);
            } else {
                algoList.add(algo);
            }
        }
        return algoList;
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(byte[] value) {
        return getSignatureAndHashAlgorithm(valueToInt(value));
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int value) {
        SignatureAndHashAlgorithm sigHashAlgo = MAP.get(value);
        return sigHashAlgo;
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(
            SignatureAlgorithm signatureAlgo, HashAlgorithm hashAlgo) {
        for (SignatureAndHashAlgorithm algo : values()) {
            if (algo.getHashAlgorithm() == hashAlgo
                    && algo.getSignatureAlgorithm() == signatureAlgo) {
                return algo;
            }
        }
        throw new UnsupportedOperationException(
                "Requested SignatureHashAlgorithm is not supported. Requested Sign:"
                        + signatureAlgo
                        + " Hash:"
                        + hashAlgo);
    }

    public byte[] getByteValue() {
        return ArrayConverter.intToBytes(value, 2);
    }

    public int getValue() {
        return value;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public boolean suitedForSigningTls13Messages() {
        switch (this) {
            case ECDSA_SHA256:
            case ECDSA_SHA384:
            case ECDSA_SHA512:
            case RSA_PSS_PSS_SHA256:
            case RSA_PSS_PSS_SHA384:
            case RSA_PSS_PSS_SHA512:
            case RSA_PSS_RSAE_SHA256:
            case RSA_PSS_RSAE_SHA384:
            case RSA_PSS_RSAE_SHA512:
            case ED25519:
            case ED448:
            case SM2_SM3:
                return true;

            default:
                return false;
        }
    }

    public boolean suitedForSigningTls13Certs() {
        switch (this) {
            case RSA_SHA256:
            case RSA_SHA384:
            case RSA_SHA512:
            case RSA_SHA1:
            case ECDSA_SHA1:
            case SM2_SM3:
                return true;

            default:
                return suitedForSigningTls13Messages();
        }
    }

    public boolean isGrease() {
        return this.name().startsWith("GREASE");
    }

    public boolean isRsaPssRsae() {
        return this == RSA_PSS_RSAE_SHA256
                || this == RSA_PSS_RSAE_SHA384
                || this == RSA_PSS_RSAE_SHA512;
    }

    public boolean suitableForSignatureKeyType(X509PublicKeyType publicKeyType) {
        if (isRsaPssRsae()) {
            return publicKeyType == X509PublicKeyType.RSA;
        } else {
            try {
                boolean usable =
                        publicKeyType.canBeUsedWithSignatureAlgorithm(this.getSignatureAlgorithm());
                return usable;
            } catch (UnsupportedOperationException ex) {
                return false;
            }
        }
    }
}
