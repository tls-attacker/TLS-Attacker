/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.hpke;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public enum HpkeKeyEncapsulationMechanism {
    RESERVED(new byte[] {(byte) 0x00, (byte) 0x00}, 0, 0, 0, 0, true, null),
    DHKEM_P256_HKDF_SHA256(
            new byte[] {(byte) 0x00, (byte) 0x10}, 32, 65, 65, 32, true, NamedGroup.SECP256R1),
    DHKEM_P384_HKDF_SHA384(
            new byte[] {(byte) 0x00, (byte) 0x11}, 48, 97, 97, 48, true, NamedGroup.SECP384R1),
    DHKEM_P521_HKDF_SHA512(
            new byte[] {(byte) 0x00, (byte) 0x12}, 64, 133, 133, 66, true, NamedGroup.SECP521R1),
    DHKEM_X25519_HKDF_SHA256(
            new byte[] {(byte) 0x00, (byte) 0x20}, 32, 32, 32, 32, true, NamedGroup.ECDH_X25519),
    DHKEM_X448_HKDF_SHA521(
            new byte[] {(byte) 0x00, (byte) 0x21}, 64, 56, 56, 56, true, NamedGroup.ECDH_X448);

    private static final Map<BigInteger, HpkeKeyEncapsulationMechanism> MAP;
    private final byte[] byteValue;
    /** nSecret in RFC 9180 */
    private final int secretLength;
    /** nEnc in RFC 9180 */
    private final int encryptionLength;
    /** nPk in RFC 9180 */
    private final int publicKeyLength;
    /** nS in RFC 9180 */
    private final int secretKeyLength;
    /** auth in RFC 9180 */
    private final boolean providesAuthentication;

    private final NamedGroup namedGroup;

    private HpkeKeyEncapsulationMechanism(
            byte[] byteValue,
            int secretLength,
            int encryptionLength,
            int publicKeyLength,
            int secretKeyLength,
            boolean providesAuthentication,
            NamedGroup namedGroup) {
        this.byteValue = byteValue;
        this.secretLength = secretLength;
        this.encryptionLength = encryptionLength;
        this.publicKeyLength = publicKeyLength;
        this.secretKeyLength = secretKeyLength;
        this.providesAuthentication = providesAuthentication;
        this.namedGroup = namedGroup;
    }

    public byte[] getByteValue() {
        return byteValue;
    }

    public int getSecretLength() {
        return secretLength;
    }

    public int getEncryptionLength() {
        return encryptionLength;
    }

    public int getPublicKeyLength() {
        return publicKeyLength;
    }

    public int getSecretKeyLength() {
        return secretKeyLength;
    }

    public boolean isProvidesAuthentication() {
        return providesAuthentication;
    }

    public NamedGroup getNamedGroup() {
        return namedGroup;
    }

    static {
        MAP = new HashMap<>();
        for (HpkeKeyEncapsulationMechanism version : HpkeKeyEncapsulationMechanism.values()) {
            byte[] versionBytes = version.getByteValue();
            if (versionBytes != null) {
                BigInteger hashMapKey = new BigInteger(versionBytes);
                MAP.put(hashMapKey, version);
            }
        }
    }

    public static HpkeKeyEncapsulationMechanism getEnumByByte(byte[] versionBytes) {
        if (versionBytes == null) {
            return HpkeKeyEncapsulationMechanism.RESERVED;
        } else {
            BigInteger hashMapKey = new BigInteger(versionBytes);
            return MAP.get(hashMapKey);
        }
    }
}
