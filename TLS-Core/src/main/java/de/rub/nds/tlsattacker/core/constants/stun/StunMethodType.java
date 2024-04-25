/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.stun;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;

public enum StunMethodType {
    BINDING("0001"),
    ALLOCATE("0003"),
    REFRESH("0004"),
    SEND("0006"),
    DATA("0007"),
    CREATE_PERMISSION("0008"),
    CHANNEL_BIND("0009"),
    CONNECT("000A"),
    CONNECTION_BIND("000B"),
    CONNECTION_ATTEMPT("000C"),
    GOOG_PING("0080");

    private byte[] value;

    private StunMethodType(String value) {
        this.value = ArrayConverter.hexStringToByteArray(value);
    }

    public byte[] getValue() {
        return value;
    }

    /**
     * Get the StunMethodType by the raw byte value as seen in the message.
     *
     * @param value
     * @return
     */
    public static StunMethodType getStunMethodTypeFromRawBytes(byte[] value) {
        if (value.length != 2) {
            throw new IllegalArgumentException("The value has to be 2 bytes long");
        }
        byte[] tempValue =
                ArrayConverter.intToBytes(conversion(ArrayConverter.bytesToInt(value)), 2);
        for (StunMethodType type : StunMethodType.values()) {
            if (Arrays.equals(type.getValue(), tempValue)) {
                return type;
            }
        }
        return null;
    }

    /** Taken from RFC 8489p.64 */
    private static int conversion(int type) {
        return (type & 0x3E00) >> 2 | (type & 0x00E0) >> 1 | (type & 0x000F);
    }
}
