/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.protocol.constants.PointFormat;
import java.io.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public enum ECPointFormat {
    UNCOMPRESSED((byte) 0, PointFormat.UNCOMPRESSED),
    ANSIX962_COMPRESSED_PRIME((byte) 1, PointFormat.ANSIX962_COMPRESSED_PRIME),
    ANSIX962_COMPRESSED_CHAR2((byte) 2, PointFormat.ANSIX962_COMPRESSED_CHAR2);

    private byte value;
    private PointFormat format;

    private static final Map<Byte, ECPointFormat> MAP;

    private ECPointFormat(byte value, PointFormat format) {
        this.value = value;
        this.format = format;
    }

    static {
        MAP = new HashMap<>();
        for (ECPointFormat cm : ECPointFormat.values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static ECPointFormat getECPointFormat(byte value) {
        return MAP.get(value);
    }

    public PointFormat getFormat() {
        return format;
    }

    public byte getValue() {
        return value;
    }

    public static ECPointFormat getRandom(Random random) {
        ECPointFormat c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (ECPointFormat) o[random.nextInt(o.length)];
        }
        return c;
    }

    public byte[] getArrayValue() {
        return new byte[] {value};
    }

    public short getShortValue() {
        return (short) (value & 0xFF);
    }

    public static byte[] pointFormatsToByteArray(List<ECPointFormat> pointFormats)
            throws IOException {
        if (pointFormats == null || pointFormats.isEmpty()) {
            return new byte[0];
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(bytes);
        os.writeObject(pointFormats.toArray(new ECPointFormat[pointFormats.size()]));

        return bytes.toByteArray();
    }

    public static ECPointFormat[] pointFormatsFromByteArray(byte[] sourceBytes)
            throws IOException, ClassNotFoundException {
        if (sourceBytes == null || sourceBytes.length == 0) {
            return null;
        }

        ByteArrayInputStream in = new ByteArrayInputStream(sourceBytes);
        ObjectInputStream is = new ObjectInputStream(in);
        ECPointFormat[] formats = (ECPointFormat[]) is.readObject();

        return formats;
    }
}
