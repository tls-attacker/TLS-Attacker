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
    RESPONSE_ADDRESS("0002"), //DEPRECATED
    CHANGE_REQUEST("0003"), //DEPRECATED
    SOURCE_ADDRESS("0004"), //DEPRECATED
    CHANGED_ADDRESS("0005"), //DEPRECATED
    USERNAME("0006"),
    PASSWORD("0007"), //DEPRECTED
    MESSAGE_INTEGRITY("0008"),
    ERROR_CODE("0009"),
    UNKNOWN_ATTRIBUTES("000A"),
    REFLECTED_FROM("000B"), //DEPRECATED
    CHANNEL_NUMBER("000C"),
    LIFETIME("000D"),
    BANDWIDTH("0010"), //DEPRECTED
    XOR_PEER_ADDRESS("0012"),
    DATA("0013"),
    REALM("0014"),
    NONCE("0015"),
    XOR_RELAYED_ADDRESS("0016"),
    REQUESTED_ADDRESS_FAMILY("0017"),
    EVEN_PORT("0018"),
    REQUESTED_TRANSPORT("0019"),
    DONT_FRAGMENT("001A"),
    ACCESS_TOKEN("001B"),
    MESSAGE_INTEGRITY_SHA256("001C"),
    PASSWORD_ALGORITHM("001D"),
    USERHASH("001E"),
    XOR_MAPPED_ADDRESS("0020"),
    TIMER_VAL("0021"),
    RESERVATION_TOKEN("0022"),
    PRIORITY("0024"),
    USE_CANDIDATE("0025"),
    PADDING("0026"),
    RESPONSE_PORT("0027"),
    CONNECTION_ID("002A"),
    ADDITIONAL_ADDRESS_FAMILY("8000"),
    ADDERSS_ERROR_CODE("8001"),
    PASSWORD_ALGORITHMS("8002"),
    ALTERNATE_DOMAIN("8003"),
    ICMP("8004"),
    SOFTWARE("8022"),
    ALTERNATE_SERVER("8023"),
    TRANSACTION_TRANSMIT_COUNTER("8025"),
    CACHE_TIMEOUT("8027"),
    FINGERPRINT("8028"),
    ICE_CONTROLLED("8029"),
    ICE_CONTROLLING("802A"),
    RESPONSE_ORIGIN("802B"),
    OTHER_ADDRESS("802C"),
    ECN_CHECK_STUN("802D"),
    THIRD_PARTY_AUTHORIZATION("802E"),
    MOBILITY_TICKET("8030"),
    CISCO_STUN_FLOWDATA("C000"),
    ENF_FLOW_DESCRIPTION("C001"),
    ENF_NETWORK_STATUS("C002"),
    CISCO_WEBEX_FLOW_INFO("C003"),
    CITRIX_TRANSACTION_ID("C056"),
    GOOG_NETWORK_INFO("C057"),
    GOOG_LAST_ICE_CHECK_RECEIVED("C058"),
    GOOG_MISC_INFO("C059"),
    GOOG_OBSOLETE_1("C05A"),
    GOOGLE_CONNECTION_ID("C05B"),
    GOOG_DELTA("C05C"),
    GOOG_DELTA_ACK("C05D"),
    GOOG_DELTA_SYNC_REQ("C05E"),
    GOOG_MESSAGE_INTEGRITY_32("C060"),
    ;

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
