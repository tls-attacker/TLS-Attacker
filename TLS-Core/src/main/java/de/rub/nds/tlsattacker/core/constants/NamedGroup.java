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
import de.rub.nds.protocol.constants.EcCurveEquationType;
import de.rub.nds.protocol.constants.GroupParameters;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ffdh.FFDHGroup;
import de.rub.nds.protocol.crypto.ffdh.GroupFFDH2048;
import de.rub.nds.protocol.crypto.ffdh.GroupFFDH3072;
import de.rub.nds.protocol.crypto.ffdh.GroupFFDH4096;
import de.rub.nds.protocol.crypto.ffdh.GroupFFDH6144;
import de.rub.nds.protocol.crypto.ffdh.GroupFFDH8192;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum NamedGroup {
    SECT163K1(new byte[] {(byte) 0, (byte) 1}, NamedEllipticCurveParameters.SECT163K1),
    SECT163R1(new byte[] {(byte) 0, (byte) 2}, NamedEllipticCurveParameters.SECT163R1),
    SECT163R2(new byte[] {(byte) 0, (byte) 3}, NamedEllipticCurveParameters.SECT163R2),
    SECT193R1(new byte[] {(byte) 0, (byte) 4}, NamedEllipticCurveParameters.SECT193R1),
    SECT193R2(new byte[] {(byte) 0, (byte) 5}, NamedEllipticCurveParameters.SECT193R2),
    SECT233K1(new byte[] {(byte) 0, (byte) 6}, NamedEllipticCurveParameters.SECT233K1),
    SECT233R1(new byte[] {(byte) 0, (byte) 7}, NamedEllipticCurveParameters.SECT233R1),
    SECT239K1(new byte[] {(byte) 0, (byte) 8}, NamedEllipticCurveParameters.SECT239K1),
    SECT283K1(new byte[] {(byte) 0, (byte) 9}, NamedEllipticCurveParameters.SECT283K1),
    SECT283R1(new byte[] {(byte) 0, (byte) 10}, NamedEllipticCurveParameters.SECT283R1),
    SECT409K1(new byte[] {(byte) 0, (byte) 11}, NamedEllipticCurveParameters.SECT409K1),
    SECT409R1(new byte[] {(byte) 0, (byte) 12}, NamedEllipticCurveParameters.SECT409R1),
    SECT571K1(new byte[] {(byte) 0, (byte) 13}, NamedEllipticCurveParameters.SECT571K1),
    SECT571R1(new byte[] {(byte) 0, (byte) 14}, NamedEllipticCurveParameters.SECT571R1),
    SECP160K1(new byte[] {(byte) 0, (byte) 15}, NamedEllipticCurveParameters.SECP160K1),
    SECP160R1(new byte[] {(byte) 0, (byte) 16}, NamedEllipticCurveParameters.SECP160R1),
    SECP160R2(new byte[] {(byte) 0, (byte) 17}, NamedEllipticCurveParameters.SECP160R2),
    SECP192K1(new byte[] {(byte) 0, (byte) 18}, NamedEllipticCurveParameters.SECP192K1),
    SECP192R1(new byte[] {(byte) 0, (byte) 19}, NamedEllipticCurveParameters.SECP192R1),
    SECP224K1(new byte[] {(byte) 0, (byte) 20}, NamedEllipticCurveParameters.SECP224K1),
    SECP224R1(new byte[] {(byte) 0, (byte) 21}, NamedEllipticCurveParameters.SECP224R1),
    SECP256K1(new byte[] {(byte) 0, (byte) 22}, NamedEllipticCurveParameters.SECP256K1),
    SECP256R1(new byte[] {(byte) 0, (byte) 23}, NamedEllipticCurveParameters.SECP256R1),
    SECP384R1(new byte[] {(byte) 0, (byte) 24}, NamedEllipticCurveParameters.SECP384R1),
    SECP521R1(new byte[] {(byte) 0, (byte) 25}, NamedEllipticCurveParameters.SECP521R1),
    BRAINPOOLP256R1(new byte[] {(byte) 0, (byte) 26}, NamedEllipticCurveParameters.BRAINPOOLP256R1),
    BRAINPOOLP384R1(new byte[] {(byte) 0, (byte) 27}, NamedEllipticCurveParameters.BRAINPOOLP384R1),
    BRAINPOOLP512R1(new byte[] {(byte) 0, (byte) 28}, NamedEllipticCurveParameters.BRAINPOOLP512R1),
    ECDH_X25519(new byte[] {(byte) 0, (byte) 29}, NamedEllipticCurveParameters.CURVE_X25519),
    ECDH_X448(new byte[] {(byte) 0, (byte) 30}, NamedEllipticCurveParameters.CURVE_X448),
    CURVE_SM2(new byte[] {(byte) 0, (byte) 41}, NamedEllipticCurveParameters.CURVE_SM2),
    FFDHE2048(new byte[] {(byte) 1, (byte) 0}, new GroupFFDH2048()),
    FFDHE3072(new byte[] {(byte) 1, (byte) 1}, new GroupFFDH3072()),
    FFDHE4096(new byte[] {(byte) 1, (byte) 2}, new GroupFFDH4096()),
    FFDHE6144(new byte[] {(byte) 1, (byte) 3}, new GroupFFDH6144()),
    FFDHE8192(new byte[] {(byte) 1, (byte) 4}, new GroupFFDH8192()),
    EXPLICIT_PRIME(new byte[] {(byte) 0xFF, (byte) 1}, null),
    // GREASE constants
    EXPLICIT_CHAR2(new byte[] {(byte) 0xFF, (byte) 2}, null),
    GREASE_00(new byte[] {(byte) 0x0A, (byte) 0x0A}, null),
    GREASE_01(new byte[] {(byte) 0x1A, (byte) 0x1A}, null),
    GREASE_02(new byte[] {(byte) 0x2A, (byte) 0x2A}, null),
    GREASE_03(new byte[] {(byte) 0x3A, (byte) 0x3A}, null),
    GREASE_04(new byte[] {(byte) 0x4A, (byte) 0x4A}, null),
    GREASE_05(new byte[] {(byte) 0x5A, (byte) 0x5A}, null),
    GREASE_06(new byte[] {(byte) 0x6A, (byte) 0x6A}, null),
    GREASE_07(new byte[] {(byte) 0x7A, (byte) 0x7A}, null),
    GREASE_08(new byte[] {(byte) 0x8A, (byte) 0x8A}, null),
    GREASE_09(new byte[] {(byte) 0x9A, (byte) 0x9A}, null),
    GREASE_10(new byte[] {(byte) 0xAA, (byte) 0xAA}, null),
    GREASE_11(new byte[] {(byte) 0xBA, (byte) 0xBA}, null),
    GREASE_12(new byte[] {(byte) 0xCA, (byte) 0xCA}, null),
    GREASE_13(new byte[] {(byte) 0xDA, (byte) 0xDA}, null),
    GREASE_14(new byte[] {(byte) 0xEA, (byte) 0xEA}, null),
    GREASE_15(new byte[] {(byte) 0xFA, (byte) 0xFA}, null);

    private static final Logger LOGGER = LogManager.getLogger();

    private byte[] value;

    private GroupParameters groupParameters;

    private static final Map<ByteBuffer, NamedGroup> MAP;

    private static final Set<NamedGroup> tls13Groups =
            new HashSet<>(
                    Arrays.asList(
                            ECDH_X25519,
                            ECDH_X448,
                            FFDHE2048,
                            FFDHE3072,
                            FFDHE4096,
                            FFDHE6144,
                            FFDHE8192,
                            SECP256R1,
                            SECP384R1,
                            SECP521R1,
                            CURVE_SM2));

    private NamedGroup(byte[] value, GroupParameters group) {
        this.value = value;
        this.groupParameters = group;
    }

    static {
        MAP = new HashMap<>();
        for (NamedGroup group : NamedGroup.values()) {
            MAP.put(ByteBuffer.wrap(group.value), group);
        }
    }

    public static NamedGroup getNamedGroup(byte[] value) {
        return MAP.get(ByteBuffer.wrap(value));
    }

    public X509NamedCurve convertToX509() {
        switch (this) {
            case BRAINPOOLP256R1:
                return X509NamedCurve.BRAINPOOLP256R1;
            case BRAINPOOLP384R1:
                return X509NamedCurve.BRAINPOOLP384R1;
            case BRAINPOOLP512R1:
                return X509NamedCurve.BRAINPOOLP512R1;
            case ECDH_X25519:
            case ECDH_X448:
                // X448 and X25519 are special values in x509 that are treated differently to
                // all
                // other curves
                return null;
            case EXPLICIT_CHAR2:
            case EXPLICIT_PRIME:
                // Not a named curve in x509
                return null;
            case FFDHE2048:
            case FFDHE3072:
            case FFDHE4096:
            case FFDHE6144:
            case FFDHE8192:
                // FFDHE has no x509 equivalent
                return null;
            case GREASE_00:
            case GREASE_01:
            case GREASE_02:
            case GREASE_03:
            case GREASE_04:
            case GREASE_05:
            case GREASE_06:
            case GREASE_07:
            case GREASE_08:
            case GREASE_09:
            case GREASE_10:
            case GREASE_11:
            case GREASE_12:
            case GREASE_13:
            case GREASE_14:
            case GREASE_15:
                // GREASE has no equivalent
                return null;
            case SECP160K1:
                return X509NamedCurve.SECP160K1;
            case SECP160R1:
                return X509NamedCurve.SECP160R1;
            case SECP160R2:
                return X509NamedCurve.SECP160R2;
            case SECP192K1:
                return X509NamedCurve.SECP192K1;
            case SECP192R1:
                return X509NamedCurve.SECP192R1;
            case SECP224K1:
                return X509NamedCurve.SECP224K1;
            case SECP224R1:
                return X509NamedCurve.SECP224R1;
            case SECP256K1:
                return X509NamedCurve.SECP256K1;
            case SECP256R1:
                return X509NamedCurve.SECP256R1;
            case SECP384R1:
                return X509NamedCurve.SECP384R1;
            case SECP521R1:
                return X509NamedCurve.SECP521R1;
            case SECT163K1:
                return X509NamedCurve.SECT163K1;
            case SECT163R1:
                return X509NamedCurve.SECT163R1;
            case SECT163R2:
                return X509NamedCurve.SECT163R2;
            case SECT193R1:
                return X509NamedCurve.SECT193R1;
            case SECT193R2:
                return X509NamedCurve.SECT193R2;
            case SECT233K1:
                return X509NamedCurve.SECT233K1;
            case SECT233R1:
                return X509NamedCurve.SECT233R1;
            case SECT239K1:
                return X509NamedCurve.SECT239K1;
            case SECT283K1:
                return X509NamedCurve.SECT283K1;
            case SECT283R1:
                return X509NamedCurve.SECT283R1;
            case SECT409K1:
                return X509NamedCurve.SECT409K1;
            case SECT409R1:
                return X509NamedCurve.SECT409R1;
            case SECT571K1:
                return X509NamedCurve.SECT571K1;
            case SECT571R1:
                return X509NamedCurve.SECT571R1;
            default:
                return null;
        }
    }

    public static NamedGroup convertFromX509NamedCurve(X509NamedCurve curve) {
        switch (curve) {
            case BRAINPOOLP160R1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP160T1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP192R1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP192T1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP224R1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP224T1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP256R1:
                return NamedGroup.BRAINPOOLP256R1;
            case BRAINPOOLP256T1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP320R1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP320T1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP384R1:
                return NamedGroup.BRAINPOOLP384R1;
            case BRAINPOOLP384T1:
                return null; // Has no TLS equivalent
            case BRAINPOOLP512R1:
                return NamedGroup.BRAINPOOLP512R1;
            case BRAINPOOLP512T1:
                return null; // Has no TLS equivalent
            case SECP112R1:
                return null; // Has no TLS equivalent
            case SECP112R2:
                return null; // Has no TLS equivalent
            case SECP128R1:
                return null; // Has no TLS equivalent
            case SECP128R2:
                return null; // Has no TLS equivalent
            case SECP160K1:
                return NamedGroup.SECP160K1;
            case SECP160R1:
                return NamedGroup.SECP160R1;
            case SECP160R2:
                return NamedGroup.SECP160R2;
            case SECP192K1:
                return NamedGroup.SECP192K1;
            case SECP192R1:
                return NamedGroup.SECP192R1;
            case SECP224K1:
                return NamedGroup.SECP224K1;
            case SECP224R1:
                return NamedGroup.SECP224R1;
            case SECP256K1:
                return NamedGroup.SECP256K1;
            case SECP256R1:
                return NamedGroup.SECP256R1;
            case SECP384R1:
                return NamedGroup.SECP384R1;
            case SECP521R1:
                return NamedGroup.SECP521R1;
            case SECT113R1:
                return null; // Has no TLS equivalent
            case SECT113R2:
                return null; // Has no TLS equivalent
            case SECT131R1:
                return null; // Has no TLS equivalent
            case SECT131R2:
                return null; // Has no TLS equivalent
            case SECT163K1:
                return NamedGroup.SECT163K1;
            case SECT163R1:
                return NamedGroup.SECT163R1;
            case SECT163R2:
                return NamedGroup.SECT163R2;
            case SECT193R1:
                return NamedGroup.SECT193R1;
            case SECT193R2:
                return NamedGroup.SECT193R2;
            case SECT233K1:
                return NamedGroup.SECT233K1;
            case SECT233R1:
                return NamedGroup.SECT233R1;
            case SECT239K1:
                return NamedGroup.SECT239K1;
            case SECT283K1:
                return NamedGroup.SECT283K1;
            case SECT283R1:
                return NamedGroup.SECT283R1;
            case SECT409K1:
                return NamedGroup.SECT409K1;
            case SECT409R1:
                return NamedGroup.SECT409R1;
            case SECT571K1:
                return NamedGroup.SECT571K1;
            case SECT571R1:
                return NamedGroup.SECT571R1;
            default:
                return null;
        }
    }

    public static NamedGroup convert(GroupParameters parameters) {
        for (NamedGroup group : NamedGroup.values()) {
            if (group.getGroupParameters() == parameters) {
                return group;
            }
        }
        return null;
    }

    public byte[] getValue() {
        return value;
    }

    public GroupParameters getGroupParameters() {
        return groupParameters;
    }

    public static NamedGroup getRandom(Random random) {
        NamedGroup c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (NamedGroup) o[random.nextInt(o.length)];
        }
        return c;
    }

    public static byte[] namedGroupsToByteArray(List<NamedGroup> groups) throws IOException {
        if (groups == null || groups.isEmpty()) {
            return new byte[0];
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (NamedGroup i : groups) {
            bytes.write(i.getValue());
        }

        return bytes.toByteArray();
    }

    public static List<NamedGroup> namedGroupsFromByteArray(byte[] sourceBytes) {
        if (sourceBytes == null || sourceBytes.length == 0) {
            return new ArrayList<>();
        }

        if (sourceBytes.length % HandshakeByteLength.NAMED_GROUP != 0) {
            throw new IllegalArgumentException(
                    "Failed to convert byte array. "
                            + "Source array size is not a multiple of destination type size.");
        }

        ByteArrayInputStream inputStream = new ByteArrayInputStream(sourceBytes);
        List<NamedGroup> groups = new ArrayList<>();
        while (inputStream.available() > 0) {
            try {
                byte[] groupBytes = inputStream.readNBytes(HandshakeByteLength.NAMED_GROUP);
                NamedGroup group = MAP.get(ByteBuffer.wrap(groupBytes));
                if (group != null) {
                    groups.add(group);
                } else {
                    LOGGER.warn(
                            "Unknown named group: {}", ArrayConverter.bytesToHexString(groupBytes));
                }
            } catch (IOException ex) {
                LOGGER.error("Could not read from ByteArrayInputStream", ex);
            }
        }
        return groups;
    }

    public boolean isShortWeierstrass() {
        if (this.isEcGroup()) {
            if (this.getGroupParameters() instanceof NamedEllipticCurveParameters) {
                return ((NamedEllipticCurveParameters) groupParameters).getEquationType()
                        == EcCurveEquationType.SHORT_WEIERSTRASS;
            } else {
                throw new UnsupportedOperationException(
                        "Unknown group parameters: " + groupParameters.getClass().getSimpleName());
            }
        } else {
            return false;
        }
    }

    @Deprecated
    public boolean isCurve() {
        return groupParameters instanceof NamedEllipticCurveParameters;
    }

    public boolean isEcGroup() {
        return groupParameters instanceof NamedEllipticCurveParameters;
    }

    public boolean isDhGroup() {
        return groupParameters instanceof FFDHGroup;
    }

    public boolean isGrease() {
        return this.name().contains("GREASE");
    }

    public static List<NamedGroup> getImplemented() {
        List<NamedGroup> list = new LinkedList<>();
        list.add(SECP160K1);
        list.add(SECP160R1);
        list.add(SECP160R2);
        list.add(SECP192K1);
        list.add(SECP192R1);
        list.add(SECP224K1);
        list.add(SECP224R1);
        list.add(SECP256K1);
        list.add(SECP256R1);
        list.add(SECP384R1);
        list.add(SECP521R1);
        list.add(SECT163K1);
        list.add(SECT163R1);
        list.add(SECT163R2);
        list.add(SECT193R1);
        list.add(SECT193R2);
        list.add(SECT233K1);
        list.add(SECT233R1);
        list.add(SECT239K1);
        list.add(SECT283K1);
        list.add(SECT283R1);
        list.add(SECT409K1);
        list.add(SECT409R1);
        list.add(SECT571K1);
        list.add(SECT571R1);
        list.add(ECDH_X25519);
        list.add(ECDH_X448);
        list.add(CURVE_SM2);
        list.add(BRAINPOOLP256R1);
        list.add(BRAINPOOLP384R1);
        list.add(BRAINPOOLP512R1);
        list.add(FFDHE2048);
        list.add(FFDHE3072);
        list.add(FFDHE4096);
        list.add(FFDHE6144);
        list.add(FFDHE8192);
        return list;
    }

    public boolean isTls13() {
        return tls13Groups.contains(this);
    }

    public boolean isGost() {
        return name().contains("GOST");
    }
}
