/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.exceptions.UnknownProtocolVersionException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum ProtocolVersion {

    SSL2(new byte[] { (byte) 0x00, (byte) 0x02 }),
    SSL3(new byte[] { (byte) 0x03, (byte) 0x00 }),
    TLS10(new byte[] { (byte) 0x03, (byte) 0x01 }),
    TLS11(new byte[] { (byte) 0x03, (byte) 0x02 }),
    TLS12(new byte[] { (byte) 0x03, (byte) 0x03 }),
    TLS13(new byte[] { (byte) 0x7F, (byte) 0x12 }),
    DTLS10(new byte[] { (byte) 0xFE, (byte) 0xFF }),
    DTLS12(new byte[] { (byte) 0xFE, (byte) 0xFD });

    private byte[] value;

    private static final Map<Integer, ProtocolVersion> MAP;

    private ProtocolVersion(byte[] value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (ProtocolVersion c : ProtocolVersion.values()) {
            MAP.put(valueToInt(c.value), c);
        }
    }

    private static Integer valueToInt(byte[] value) {
        if (value.length == 2) {
            return (value[0] & 0xff) << 8 | (value[1] & 0xff);
        } else {
            return null;
        }
    }

    public boolean isDTLS() {
        return this == DTLS10 || this == DTLS12;
    }

    public static ProtocolVersion getProtocolVersion(byte[] value) {
        Integer i = valueToInt(value);
        if (i == null) {
            return null;
        }
        return MAP.get(i);
    }

    public static List<ProtocolVersion> getProtocolVersions(byte[] values) {
        List<ProtocolVersion> versions = new LinkedList<>();
        if (values.length % 2 != 0) {
            throw new UnknownProtocolVersionException("Last ProtocolVersion are unknown!");
        }
        int pointer = 0;
        while (pointer < values.length) {
            byte[] version = new byte[2];
            version[0] = values[pointer];
            version[1] = values[pointer + 1];
            if (version == null) {
                throw new UnknownProtocolVersionException("Unknown ProtocolVersion!");
            } else {
                versions.add(getProtocolVersion(version));
            }
            pointer += 2;
        }
        return versions;
    }

    public static ProtocolVersion getRandom() {
        ProtocolVersion c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (ProtocolVersion) o[RandomHelper.getRandom().nextInt(o.length)];
        }
        return c;
    }

    public byte[] getValue() {
        return value;
    }

    public byte getMajor() {
        return value[0];
    }

    public byte getMinor() {
        return value[1];
    }

    /**
     * Maps a string protocol version value to an enum.
     *
     * It handles specific cases like TLSv1.2 or SSLv3
     *
     * @param protocolVersion
     * @return
     */
    public static ProtocolVersion fromString(String protocolVersion) {
        protocolVersion = protocolVersion.replaceFirst("v", "");
        protocolVersion = protocolVersion.replaceFirst("\\.", "");
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if (protocolVersion.equalsIgnoreCase(pv.toString())) {
                return pv;
            }
        }
        throw new IllegalArgumentException("Value " + protocolVersion + " cannot be converted to a protocol version. "
                + "Available values are: " + Arrays.toString(ProtocolVersion.values()));
    }

    /**
     * Return the highest protcol version.
     * 
     * @param list
     * @return
     */
    public static ProtocolVersion gethighestProtocolVersion(List<ProtocolVersion> list) {
        ProtocolVersion highestProtocolVersion = list.get(0);
        for (ProtocolVersion pv : list) {
            if (ArrayConverter.bytesToInt(pv.getValue()) > ArrayConverter.bytesToInt(highestProtocolVersion.getValue())) {
                highestProtocolVersion = pv;
            }
        }
        return highestProtocolVersion;
    }

}
