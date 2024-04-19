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

public enum StunMessageType {
    BINDING_REQUEST("0001"),
    BINDING_RESPONSE("0101"),
    BINDING_ERROR_RESPONSE("0111"),
    SHARED_SECRET_REQUEST("0002"),
    SHARED_SECRET_RESPONSE("0102"),
    SHARED_SECRET_ERROR_RESPONSE("0112"),
    ALLOCATE("0003"),
    REFRESH("0004"),
    SEND("0006"),
    DATA("0007"),
    CREATE_PERMISSION("0008"),
    CHANNEL_BIND("0009");

    private byte[] value;

    private StunMessageType(String value) {
        this.value = ArrayConverter.hexStringToByteArray(value);
    }

    public byte[] getValue() {
        return value;
    }
}
