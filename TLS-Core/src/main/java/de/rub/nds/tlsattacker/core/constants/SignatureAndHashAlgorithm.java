/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.UnknownSignatureAndHashAlgorithm;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Construction of a hash and signature algorithm. Very confusing, consists of
 * two bytes, the first is hash algorithm: {HashAlgorithm, SignatureAlgorithm}
 */
public enum SignatureAndHashAlgorithm {
    ANONYMOUS_NONE(0x0000),
    ANONYMOUS_MD5(0x0100),
    ANONYMOUS_SHA1(0x0200),
    ANONYMOUS_SHA224(0x0300),
    ANONYMOUS_SHA256(0x0400),
    ANONYMOUS_SHA384(0x0500),
    ANONYMOUS_SHA512(0x0600),
    RSA_NONE(0x0001),
    RSA_MD5(0x0101),
    RSA_SHA1(0x0201),
    RSA_SHA224(0x0301),
    RSA_SHA256(0x0401),
    RSA_SHA384(0x0501),
    RSA_SHA512(0x0601),
    DSA_NONE(0x0002),
    DSA_MD5(0x0102),
    DSA_SHA1(0x0202),
    DSA_SHA224(0x0302),
    DSA_SHA256(0x0402),
    DSA_SHA384(0x0502),
    DSA_SHA512(0x0602),
    ECDSA_NONE(0x0003),
    ECDSA_MD5(0x0103),
    ECDSA_SHA1(0x0203),
    ECDSA_SHA224(0x0303),
    ECDSA_SHA256(0x0403),
    ECDSA_SHA384(0x0503),
    ECDSA_SHA512(0x0603),
    ED25519(0x0807),
    ED448(0x0808),
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RSA_PSS_RSAE_SHA256(0x0804),
    RSA_PSS_RSAE_SHA384(0x0805),
    RSA_PSS_RSAE_SHA512(0x0806),
    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RSA_PSS_PSS_SHA256(0x0809),
    RSA_PSS_PSS_SHA384(0x080a),
    RSA_PSS_PSS_SHA512(0x080b),
    GOSTR34102001_GOSTR3411(0xEDED),
    GOSTR34102012_256_GOSTR34112012_256(0xEEEE),
    GOSTR34102012_512_GOSTR34112012_512(0xEFEF);

    private static final Logger LOGGER = LogManager.getLogger();

    public static List<? extends SignatureAndHashAlgorithm> getImplemented() {
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(DSA_MD5);
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
        algoList.add(ECDSA_MD5);
        algoList.add(ECDSA_SHA1);
        algoList.add(ECDSA_SHA224);
        algoList.add(ECDSA_SHA256);
        algoList.add(ECDSA_SHA384);
        algoList.add(ECDSA_SHA512);
        algoList.add(GOSTR34102001_GOSTR3411);
        algoList.add(GOSTR34102012_256_GOSTR34112012_256);
        algoList.add(GOSTR34102012_512_GOSTR34112012_512);
        return algoList;
    }

    private int value;

    private static final Map<Integer, SignatureAndHashAlgorithm> MAP;

    private SignatureAndHashAlgorithm(int value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (SignatureAndHashAlgorithm c : SignatureAndHashAlgorithm.values()) {
            MAP.put(c.value, c);
        }
    }

    private static int valueToInt(byte[] value) {
        if (value.length >= 2) {
            return (value[0] & 0xff) << 8 | (value[1] & 0xff);
        } else if (value.length == 1) {
            return value[0];
        } else {
            return 0;
        }
    }

    public static List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms(byte[] values) {
        List<SignatureAndHashAlgorithm> sigHashAlgoList = new LinkedList<>();
        int pointer = 0;
        if (values.length % 2 != 0) {
            throw new UnknownSignatureAndHashAlgorithm("ByteArray is not divisible by 2!");
        }
        while (pointer < values.length) {
            byte[] sigHashAlgo = new byte[2];
            sigHashAlgo[0] = values[pointer];
            sigHashAlgo[1] = values[pointer + 1];
            sigHashAlgoList.add(getSignatureAndHashAlgorithm(sigHashAlgo));
            pointer += 2;
        }
        return sigHashAlgoList;
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(byte[] value) {
        return getSignatureAndHashAlgorithm(valueToInt(value));
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int value) {
        SignatureAndHashAlgorithm sigHashAlgo = MAP.get(value);
        return sigHashAlgo;
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(SignatureAlgorithm signatureAlgo,
            HashAlgorithm hashAlgo) {
        for (SignatureAndHashAlgorithm algo : values()) {
            if (algo.getHashAlgorithm() == hashAlgo && algo.getSignatureAlgorithm() == signatureAlgo) {
                return algo;
            }
        }
        throw new UnsupportedOperationException("Requested SignatureHashAlgorithm is not supported. Requested Sign:"
                + signatureAlgo + " Hash:" + hashAlgo);
    }

    public byte[] getByteValue() {
        return ArrayConverter.intToBytes(value, 2);
    }

    public int getValue() {
        return value;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        SignatureAlgorithm bestMatch = null;
        for (SignatureAlgorithm algo : SignatureAlgorithm.values()) {
            if (this.name().contains(algo.name())) {
                if (bestMatch == null || bestMatch.name().length() < algo.name().length()) {
                    bestMatch = algo;
                }
            }
        }
        if (bestMatch != null) {
            return bestMatch;
        }
        return SignatureAlgorithm.ANONYMOUS;
    }

    public HashAlgorithm getHashAlgorithm() {
        HashAlgorithm bestMatch = null;
        for (HashAlgorithm algo : HashAlgorithm.values()) {
            if (this.name().contains(algo.name())) {
                if (bestMatch == null || bestMatch.name().length() < algo.name().length()) {
                    bestMatch = algo;
                }
            }
        }
        if (bestMatch != null) {
            return bestMatch;
        }
        return HashAlgorithm.NONE;
    }

    public String getJavaName() {
        String hashAlgorithmName = getHashAlgorithm().getJavaName();
        if (!hashAlgorithmName.contains("GOST")) {
            hashAlgorithmName = hashAlgorithmName.replace("-", "");
        }
        String signatureAlgorithmName = getSignatureAlgorithm().getJavaName();
        return hashAlgorithmName + "with" + signatureAlgorithmName;
    }

}
