/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.factory;

import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.stun.model.DataAttribute;
import de.rub.nds.tlsattacker.core.stun.model.ErrorCodeAttribute;
import de.rub.nds.tlsattacker.core.stun.model.MessageIntegrityAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;
import de.rub.nds.tlsattacker.core.stun.model.UnknownAttribute;
import de.rub.nds.tlsattacker.core.stun.model.UsernameAttribute;
import de.rub.nds.tlsattacker.core.stun.model.XorMappedAddressAttribute;

public class AttributeFactory {
    private AttributeFactory() {}

    public static StunAttribute createAttribute(StunAttributeType type) {
        switch (type) {
            case DATA:
                return new DataAttribute();
            case ERROR_CODE:
                return new ErrorCodeAttribute();
            case MAPPED_ADDRESS:
                return new XorMappedAddressAttribute();
            case MESSAGE_INTEGRITY:
                return new MessageIntegrityAttribute();
            case USERNAME:
                return new UsernameAttribute();
            case XOR_PEER_ADDRESS:
            case XOR_RELAYED_ADDRESS:
            case CHANGED_ADDRESS:
            case CHANNEL_NUMBER:
            case CHANGE_REQUEST:
            case DONT_FRAGMENT:
            case EVEN_PORT:
            case LIFETIME:
            case PASSWORD:
            case REFLECTED_FROM:
            case REQUESTED_TRANSPORT:
            case RESERVATION_TOKEN:
            case RESERVED_WAS_TIMER_VAL:
            case RESERVER_WAS_BANDWIDTH:
            case RESPONSE_ADDRESS:
            case SOURCE_ADDRESS:
            case UNKNOWN_ATTRIBUTES:
                throw new UnsupportedOperationException("Attribute type not supported yet");
            default:
                return new UnknownAttribute();
        }
    }
}
