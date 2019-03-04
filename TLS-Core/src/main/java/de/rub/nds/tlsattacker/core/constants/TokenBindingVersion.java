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
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public enum TokenBindingVersion {
    DRAFT_1(new byte[] { (byte) 0, (byte) 1 }),
    DRAFT_2(new byte[] { (byte) 0, (byte) 2 }),
    DRAFT_3(new byte[] { (byte) 0, (byte) 3 }),
    DRAFT_4(new byte[] { (byte) 0, (byte) 4 }),
    DRAFT_5(new byte[] { (byte) 0, (byte) 5 }),
    DRAFT_6(new byte[] { (byte) 0, (byte) 6 }),
    DRAFT_7(new byte[] { (byte) 0, (byte) 7 }),
    DRAFT_8(new byte[] { (byte) 0, (byte) 8 }),
    DRAFT_9(new byte[] { (byte) 0, (byte) 9 }),
    DRAFT_10(new byte[] { (byte) 0, (byte) 0xA }),
    DRAFT_11(new byte[] { (byte) 0, (byte) 0xB }),
    DRAFT_12(new byte[] { (byte) 0, (byte) 0xC }),
    DRAFT_13(new byte[] { (byte) 0, (byte) 0xD }),
    DRAFT_14(new byte[] { (byte) 0, (byte) 0xE }),
    DRAFT_15(new byte[] { (byte) 0, (byte) 0xF }),
    DRAFT_16(new byte[] { (byte) 0, (byte) 0x10 }),
    DRAFT_17(new byte[] { (byte) 0, (byte) 0x11 }),
    DRAFT_18(new byte[] { (byte) 0, (byte) 0x12 });

    private final byte[] tokenBindingVersion;
    public static final int LENGTH = 2;

    private static final Map<Integer, TokenBindingVersion> MAP;

    static {
        MAP = new HashMap<>();
        for (TokenBindingVersion c : TokenBindingVersion.values()) {
            MAP.put(ArrayConverter.bytesToInt(c.tokenBindingVersion), c);
        }
    }

    private TokenBindingVersion(byte[] tokenBindingVersion) {
        this.tokenBindingVersion = tokenBindingVersion;
    }

    public byte[] getByteValue() {
        return tokenBindingVersion;
    }

    public static TokenBindingVersion getExtensionType(byte[] value) {
        TokenBindingVersion type = MAP.get(ArrayConverter.bytesToInt(value));
        return type;
    }

    public byte getMajor() {
        return tokenBindingVersion[0];
    }

    public byte getMinor() {
        return tokenBindingVersion[1];
    }

    public static TokenBindingVersion getRandom(Random random) {
        TokenBindingVersion c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (TokenBindingVersion) o[random.nextInt(o.length)];
        }
        return c;
    }
}
