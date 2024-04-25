/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.stun;

public enum StunMessageClass {
    REQUEST((byte) 0x00),
    INDICATION((byte) 0x01),
    SUCCESS_RESPONSE((byte) 0x10),
    ERROR_RESPONSE((byte) 0x11);

    private byte value;

    private StunMessageClass(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    public static StunMessageClass getMessageClass(byte value) {
        for (StunMessageClass cls : StunMessageClass.values()) {
            if (cls.getValue() == value) {
                return cls;
            }
        }
        return null;
    }

    /**
     * Returns the StunMessageClass for the given 2 byte messageTypeBytes
     *
     * @param messageTypeBytes
     * @return
     */
    public static StunMessageClass getMessageClass(byte[] messageTypeBytes) {
        if (messageTypeBytes.length != 2) {
            throw new IllegalArgumentException("The messageTypeBytes have to be 2 bytes long");
        }
        // Technically, the message type is 12 bits long, we internally treat them as if they were 2
        // bytes long
        // the lsb of byte[0] and the bit 5 of the last byte of the type bytes form the message
        // class (concatenated).
        byte value =
                (byte)
                        ((byte) (messageTypeBytes[1] & 0x01 << 1)
                                | (byte) (messageTypeBytes[0] & 0x10));
        return getMessageClass(value);
    }
}
