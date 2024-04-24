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
}
