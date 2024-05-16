/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.stun;

public class IceByteLengths {
    public static final int STUN_MESSAGE_TYPE = 2;

    public static final int STUN_MESSAGE_LENGTH = 2;

    public static final int STUN_MAGIC_COOKIE = 4;

    /** This is the lenght inclusive of the TransactionId */
    public static final int STUN_TRANSACTION_ID = 16;

    public static final int STUN_ATTRIBUTE_TYPE = 2;

    public static final int STUN_ATTRIBUTE_LENGTH = 2;

    /** All Stun attributes have to be a multiple of 4 bytes */
    public static final int STUN_ATTRIBUTE_ALIGNMENT = 4;

    public static final int STUN_XOR_MAPPED_ATTRIBUTE_PORT = 2;
    public static final int STUN_XOR_PEER_ATTRIBUTE_PORT = 2;

    public static final int STUN_XOR_MAPPED_ATTRIBUTE_RESERVED = 1;

    public static final int STUN_XOR_PEER_ATTRIBUTE_RESERVED = 1;

    public static final int STUN_XOR_MAPPED_ATTRIBUTE_PROTOCOL_FAMILY = 1;

    public static final int STUN_XOR_PEER_ATTRIBUTE_PROTOCOL_FAMILY = 1;

    public static final int STUN_PRIORITY_LENGTH = 4;

    public static final int STUN_ICE_CONTROLLED_TIE_BREAKER = 8;

    public static final int STUN_MESSAGE_INTEGRITY_HMAC = 20;

    public static final int STUN_FINGERPRINT_CRC_CHECKSUM = 4;

    /** This is technically 21 bits - but we just ignore this */
    public static final int STUN_ERROR_CODE_RESERVED_BYTES = 2;

    /** This is technically 3 bits - but we just ignore this */
    public static final int STUN_ERROR_CLASS = 1;

    public static final int STUN_ERROR_VALUE = 1;

    public static final int CRC32_CHECKSUM = 4;

    public static final int STUN_METHOD_TYPE = 2;

    public static final int TURN_CHANNEL_NUMBER = 0;

    public static final int TURN_CHANNEL_DATA_LENGTH = 0;

    private IceByteLengths() {}
}
