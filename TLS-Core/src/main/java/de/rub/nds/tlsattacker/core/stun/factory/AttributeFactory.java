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
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.stun.model.IceControlledAttribute;
import de.rub.nds.tlsattacker.core.stun.model.IceControllingAttribute;
import de.rub.nds.tlsattacker.core.stun.model.MessageIntegrityAttribute;
import de.rub.nds.tlsattacker.core.stun.model.PriorityAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;
import de.rub.nds.tlsattacker.core.stun.model.UnknownAttribute;
import de.rub.nds.tlsattacker.core.stun.model.UseCandidateAttribute;
import de.rub.nds.tlsattacker.core.stun.model.UsernameAttribute;
import de.rub.nds.tlsattacker.core.stun.model.XorMappedAddressAttribute;

public class AttributeFactory {
    private AttributeFactory() {
    }

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
            case USE_CANDIDATE:
                return new UseCandidateAttribute();
            case PRIORITY:
                return new PriorityAttribute();
            case ICE_CONTROLLED:
                return new IceControlledAttribute();
            case ICE_CONTROLLING:
                return new IceControllingAttribute();
            case FINGERPRINT:
                return new FingerprintAttribute();
            case ADDERSS_ERROR_CODE:
            case ADDITIONAL_ADDRESS_FAMILY:
            case ALTERNATE_DOMAIN:
            case ALTERNATE_SERVER:
            case BANDWIDTH:
            case CHANGE_REQUEST:
            case CACHE_TIMEOUT:
            case REALM:
            case NONCE:
            case SOFTWARE:
            case ACCESS_TOKEN:
            case XOR_PEER_ADDRESS:
            case XOR_RELAYED_ADDRESS:
            case CHANGED_ADDRESS:
            case CHANNEL_NUMBER:
            case DONT_FRAGMENT:
            case EVEN_PORT:
            case LIFETIME:
            case PASSWORD:
            case REFLECTED_FROM:
            case REQUESTED_TRANSPORT:
            case RESERVATION_TOKEN:
            case RESPONSE_ADDRESS:
            case SOURCE_ADDRESS:
            case UNKNOWN_ATTRIBUTES:
            case CISCO_STUN_FLOWDATA:
            case CISCO_WEBEX_FLOW_INFO:
            case CITRIX_TRANSACTION_ID:
            case CONNECTION_ID:
            case ECN_CHECK_STUN:
            case ENF_FLOW_DESCRIPTION:
            case ENF_NETWORK_STATUS:
            case ICMP:
            case MOBILITY_TICKET:
            case OTHER_ADDRESS:
            case PADDING:
            case PASSWORD_ALGORITHM:
            case PASSWORD_ALGORITHMS:
            case REQUESTED_ADDRESS_FAMILY:
            case RESPONSE_ORIGIN:
            case RESPONSE_PORT:
            case TIMER_VAL:
            case TRANSACTION_TRANSMIT_COUNTER:
            case USERHASH:
            case GOOG_NETWORK_INFO:
            case THIRD_PARTY_AUTHORIZATION:
            case MESSAGE_INTEGRITY_SHA256:
            case GOOG_DELTA:
            default:
                return new UnknownAttribute();
        }
    }
}
