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

public enum StunAttributeType {
    MAPPED_ADDRESS("0001"),
    RESPONSE_ADDRESS("0002"),
    CHANGE_REQUEST("0003"),
    SOURCE_ADDRESS("0004"),
    CHANGED_ADDRESS("0005"),
    USERNAME("0006"),
    PASSWORD("0007"),
    MESSAGE_INTEGRITY("0008"),
    ERROR_CODE("0009"),
    UNKNOWN_ATTRIBUTES("000A"),
    REFLECTED_FROM("000B"),
    CHANNEL_NUMBER("000C"),
    LIFETIME("000D"),
    RESERVER_WAS_BANDWIDTH("0010"),
    XOR_PEER_ADDRESS("0012"),
    DATA("0013"),
    XOR_RELAYED_ADDRESS("0016"),
    EVEN_PORT("0018"),
    REQUESTED_TRANSPORT("0019"),
    DONT_FRAGMENT("001A"),
    RESERVED_WAS_TIMER_VAL("0021"),
    RESERVATION_TOKEN("0022");

    private byte[] value;

    private StunAttributeType(String value) {
        this.value = ArrayConverter.hexStringToByteArray(value);
    }

    public byte[] getValue() {
        return value;
    }

    public static StunAttributeType getAttributeType(byte[] value) {
        for (StunAttributeType type : StunAttributeType.values()) {
            if (Arrays.equals(type.value, value)) {
                return type;
            }
        }
        return null;
    }
}
