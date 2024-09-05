/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

import java.util.HashMap;
import java.util.Map;

public enum QuicFrameType {
    UNKNOWN((byte) 255),
    PADDING_FRAME((byte) 0x00),
    PING_FRAME((byte) 0x01),
    ACK_FRAME((byte) 0x02),
    ACK_FRAME_WITH_ECN((byte) 0x03),
    RESET_STREAM_FRAME((byte) 0x04),
    STOP_SENDING_FRAME((byte) 0x05),
    CRYPTO_FRAME((byte) 0x06),
    NEW_TOKEN_FRAME((byte) 0x07),
    STREAM_FRAME((byte) 0x08),
    STREAM_FRAME_FIN((byte) 0x09),
    DATAGRAM_FRAME_LEN((byte) 0x0a),
    STREAM_FRAME_LEN_FIN((byte) 0x0b),
    STREAM_FRAME_OFF((byte) 0x0c),
    STREAM_FRAME_OFF_FIN((byte) 0x0d),
    STREAM_FRAME_OFF_LEN((byte) 0x0e),
    STREAM_FRAME_OFF_LEN_FIN((byte) 0x0f),
    MAX_DATA_FRAME((byte) 0x10),
    MAX_STREAM_DATA_FRAME((byte) 0x11),
    MAX_STREAMS_BIDI_FRAME((byte) 0x12),
    MAX_STREAMS_UNI_FRAME((byte) 0x13),
    DATA_BLOCKED_FRAME((byte) 0x14),
    STREAM_DATA_BLOCKED_FRAME((byte) 0x15),
    STREAMS_BLOCKED_BIDI_FRAME((byte) 0x16),
    STREAMS_BLOCKED_UNI_FRAME((byte) 0x17),
    NEW_CONNECTION_ID_FRAME((byte) 0x18),
    RETIRE_CONNECTION_ID((byte) 0x19),
    PATH_CHALLENGE_FRAME((byte) 0x1a),
    PATH_RESPONSE_FRAME((byte) 0x1b),
    CONNECTION_CLOSE_QUIC_FRAME((byte) 0x1c),
    CONNECTION_CLOSE_APPLICATION_FRAME((byte) 0x1d),
    HANDSHAKE_DONE_FRAME((byte) 0x1e),
    DATAGRAM_FRAME((byte) 0x30),
    STREAM_FRAME_LEN((byte) 0x31);

    private int value;
    private static final Map<Byte, QuicFrameType> MAP;

    private QuicFrameType(byte value) {
        this.value = value;
    }

    private QuicFrameType() {
        this.value = -1;
    }

    static {
        MAP = new HashMap<>();
        for (QuicFrameType type : QuicFrameType.values()) {
            if (type == UNKNOWN) {
                continue;
            }
            MAP.put((byte) type.value, type);
        }
    }

    public static QuicFrameType getFrameType(byte value) {
        QuicFrameType type = MAP.get(value);
        if (type == null) {
            type = UNKNOWN;
        }
        return type;
    }

    public byte getValue() {
        return (byte) value;
    }

    public String getName() {
        return this.name();
    }
}
