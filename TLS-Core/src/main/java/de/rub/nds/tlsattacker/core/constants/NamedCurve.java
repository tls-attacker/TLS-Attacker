/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.RandomHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum NamedCurve {

    SECT163K1(new byte[] { (byte) 0, (byte) 1 }, "sect163k1"),
    SECT163R1(new byte[] { (byte) 0, (byte) 2 }, "sect163r1"),
    SECT163R2(new byte[] { (byte) 0, (byte) 3 }, "sect163r2"),
    SECT193R1(new byte[] { (byte) 0, (byte) 4 }, "sect193r1"),
    SECT193R2(new byte[] { (byte) 0, (byte) 5 }, "sect193r2"),
    SECT233K1(new byte[] { (byte) 0, (byte) 6 }, "sect233k1"),
    SECT233R1(new byte[] { (byte) 0, (byte) 7 }, "sect233r1"),
    SECT239K1(new byte[] { (byte) 0, (byte) 8 }, "sect239k1"),
    SECT283K1(new byte[] { (byte) 0, (byte) 9 }, "sect283k1"),
    SECT283R1(new byte[] { (byte) 0, (byte) 10 }, "sect283r1"),
    SECT409K1(new byte[] { (byte) 0, (byte) 11 }, "sect409k1"),
    SECT409R1(new byte[] { (byte) 0, (byte) 12 }, "sect409r1"),
    SECT571K1(new byte[] { (byte) 0, (byte) 13 }, "sect571k1"),
    SECT571R1(new byte[] { (byte) 0, (byte) 14 }, "sect571r1"),
    SECP160K1(new byte[] { (byte) 0, (byte) 15 }, "secp160k1"),
    SECP160R1(new byte[] { (byte) 0, (byte) 16 }, "secp160r1"),
    SECP160R2(new byte[] { (byte) 0, (byte) 17 }, "secp160r2"),
    SECP192K1(new byte[] { (byte) 0, (byte) 18 }, "secp192k1"),
    SECP192R1(new byte[] { (byte) 0, (byte) 19 }, "secp192r1"),
    SECP224K1(new byte[] { (byte) 0, (byte) 20 }, "secp224k1"),
    SECP224R1(new byte[] { (byte) 0, (byte) 21 }, "secp224r1"),
    SECP256K1(new byte[] { (byte) 0, (byte) 22 }, "secp256k1"),
    SECP256R1(new byte[] { (byte) 0, (byte) 23 }, "secp256r1"),
    SECP384R1(new byte[] { (byte) 0, (byte) 24 }, "secp384r1"),
    SECP521R1(new byte[] { (byte) 0, (byte) 25 }, "secp521r1"),
    BRAINPOOLP256R1(new byte[] { (byte) 0, (byte) 26 }, "brainpoolp256r1"), // incorrect
                                                                            // java
                                                                            // name
    BRAINPOOLP384R1(new byte[] { (byte) 0, (byte) 27 }, "brainpoolp384r1"), // incorrect
                                                                            // java
                                                                            // name
    BRAINPOOLP512R1(new byte[] { (byte) 0, (byte) 28 }, "brainpoolp512r1"), // incorrect
                                                                            // java
                                                                            // name
    ECDH_X25519(new byte[] { (byte) 0, (byte) 29 }, "ecdh_X25519"), // incorrect
                                                                    // java name
    ECDH_X448(new byte[] { (byte) 0, (byte) 30 }, "ecdh_X448"), // incorrect
                                                                // java name
    FFDHE2048(new byte[] { (byte) 1, (byte) 0 }, "FFDHE2048"), // incorrect java
                                                               // name
    FFDHE3072(new byte[] { (byte) 1, (byte) 1 }, "FFDHE3072"), // incorrect java
                                                               // name
    FFDHE4096(new byte[] { (byte) 1, (byte) 2 }, "FFDHE4096"), // incorrect java
                                                               // name
    FFDHE6144(new byte[] { (byte) 1, (byte) 3 }, "FFDHE6144"), // incorrect java
                                                               // name
    FFDHE8192(new byte[] { (byte) 1, (byte) 4 }, "FFDHE8192"), // incorrect java
                                                               // name
    // TODO Grease logic implementation, because the tests fail if the lines
    // aren't commented
    // GREASE constants
    // GREASE_00(new byte[] { (byte) 0x0A, (byte) 0x0A }),
    // GREASE_01(new byte[] { (byte) 0x1A, (byte) 0x1A }),
    // GREASE_02(new byte[] { (byte) 0x2A, (byte) 0x2A }),
    // GREASE_03(new byte[] { (byte) 0x3A, (byte) 0x3A }),
    // GREASE_04(new byte[] { (byte) 0x4A, (byte) 0x4A }),
    // GREASE_05(new byte[] { (byte) 0x5A, (byte) 0x5A }),
    // GREASE_06(new byte[] { (byte) 0x6A, (byte) 0x6A }),
    // GREASE_07(new byte[] { (byte) 0x7A, (byte) 0x7A }),
    // GREASE_08(new byte[] { (byte) 0x8A, (byte) 0x8A }),
    // GREASE_09(new byte[] { (byte) 0x9A, (byte) 0x9A }),
    // GREASE_10(new byte[] { (byte) 0xAA, (byte) 0xAA }),
    // GREASE_11(new byte[] { (byte) 0xBA, (byte) 0xBA }),
    // GREASE_12(new byte[] { (byte) 0xCA, (byte) 0xCA }),
    // GREASE_13(new byte[] { (byte) 0xDA, (byte) 0xDA }),
    // GREASE_14(new byte[] { (byte) 0xEA, (byte) 0xEA }),
    // GREASE_15(new byte[] { (byte) 0xFA, (byte) 0xFA }),
    NONE(new byte[] { (byte) 0, (byte) 0 }, "");

    public static final int LENGTH = 2;

    private byte[] value;

    private String javaName;

    private static final Map<Integer, NamedCurve> MAP;

    private NamedCurve(byte[] value, String javaName) {
        this.value = value;
        this.javaName = javaName;
    }

    static {
        MAP = new HashMap<>();
        for (NamedCurve c : NamedCurve.values()) {
            MAP.put(valueToInt(c.value), c);
        }
    }

    public String getJavaName() {
        return javaName;
    }

    public void setJavaName(String javaName) {
        this.javaName = javaName;
    }

    private static int valueToInt(byte[] value) {
        return (value[0] & 0xff) << 8 | (value[1] & 0xff);
    }

    public static NamedCurve getNamedCurve(byte[] value) {
        return MAP.get(valueToInt(value));
    }

    public byte[] getValue() {
        return value;
    }

    public static NamedCurve getRandom() {
        NamedCurve c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (NamedCurve) o[RandomHelper.getRandom().nextInt(o.length)];
        }
        return c;
    }

    public int getIntValue() {
        return valueToInt(value);
    }

    public static byte[] namedCurvesToByteArray(List<NamedCurve> curves) throws IOException {
        if (curves == null || curves.isEmpty()) {
            return new byte[0];
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(bytes);
        os.writeObject(curves.toArray(new NamedCurve[curves.size()]));

        return bytes.toByteArray();
    }

    public static NamedCurve[] namedCurvesFromByteArray(byte[] sourceBytes) throws IOException, ClassNotFoundException {
        if (sourceBytes == null || sourceBytes.length == 0) {
            return new NamedCurve[0];
        }

        if (sourceBytes.length % NamedCurve.LENGTH != 0) {
            throw new IllegalArgumentException("Failed to convert byte array. "
                    + "Source array size is not a multiple of destination type size.");
        }

        ByteArrayInputStream in = new ByteArrayInputStream(sourceBytes);
        ObjectInputStream is = new ObjectInputStream(in);
        NamedCurve[] curves = (NamedCurve[]) is.readObject();

        return curves;
    }

    public static List<NamedCurve> getImplemented() {
        List<NamedCurve> list = new LinkedList<>();
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

        return list;
    }
}
