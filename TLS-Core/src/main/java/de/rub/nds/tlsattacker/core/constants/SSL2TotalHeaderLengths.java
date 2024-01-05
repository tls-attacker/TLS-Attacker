/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public enum SSL2TotalHeaderLengths {
    NO_PADDING(0x80),
    WITH_PADDING(0x70),
    ALL_BUT_ONE_BIT(0x7f),
    ALL_BUT_TWO_BIT(0x37);

    private int value;

    SSL2TotalHeaderLengths(int value) {
        this.value = value;
    }

    public int getValue() {
        return this.value;
    }

    public void setValue(int value) {
        this.value = value;
    }

    /*
     * draft-hickman-netscape-ssl-00.txt: "If the most significant bit is set in the first byte of the record
     * length code then the record has no padding and the total header length will be 2 bytes, otherwise the
     * record has padding and the total header length will be 3 bytes."
     */
    public static boolean isNoPaddingHeader(byte header) {
        return (header & SSL2TotalHeaderLengths.NO_PADDING.getValue())
                == SSL2TotalHeaderLengths.NO_PADDING.getValue();
    }
}
