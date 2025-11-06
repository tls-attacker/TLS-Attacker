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
    UNKNOWN(0x7fffffffffffffffL),
    PADDING_FRAME(0x00),
    PING_FRAME(0x01),
    ACK_FRAME(0x02),
    ACK_FRAME_WITH_ECN(0x03),
    RESET_STREAM_FRAME(0x04),
    STOP_SENDING_FRAME(0x05),
    CRYPTO_FRAME(0x06),
    NEW_TOKEN_FRAME(0x07),
    STREAM_FRAME(0x08),
    STREAM_FRAME_FIN(0x09),
    STREAM_FRAME_LEN(0x0a),
    STREAM_FRAME_LEN_FIN(0x0b),
    STREAM_FRAME_OFF(0x0c),
    STREAM_FRAME_OFF_FIN(0x0d),
    STREAM_FRAME_OFF_LEN(0x0e),
    STREAM_FRAME_OFF_LEN_FIN(0x0f),
    MAX_DATA_FRAME(0x10),
    MAX_STREAM_DATA_FRAME(0x11),
    MAX_STREAMS_BIDI_FRAME(0x12),
    MAX_STREAMS_UNI_FRAME(0x13),
    DATA_BLOCKED_FRAME(0x14),
    STREAM_DATA_BLOCKED_FRAME(0x15),
    STREAMS_BLOCKED_BIDI_FRAME(0x16),
    STREAMS_BLOCKED_UNI_FRAME(0x17),
    NEW_CONNECTION_ID_FRAME(0x18),
    RETIRE_CONNECTION_ID(0x19),
    PATH_CHALLENGE_FRAME(0x1a),
    PATH_RESPONSE_FRAME(0x1b),
    CONNECTION_CLOSE_QUIC_FRAME(0x1c),
    CONNECTION_CLOSE_APPLICATION_FRAME(0x1d),
    HANDSHAKE_DONE_FRAME(0x1e),
    DATAGRAM_FRAME(0x30),
    DATAGRAM_FRAME_LEN(0x31);

    private final long value;
    private static final Map<Long, QuicFrameType> MAP;

    QuicFrameType(long value) {
        this.value = value;
    }

    QuicFrameType() {
        this.value = -1;
    }

    static {
        MAP = new HashMap<>();
        for (QuicFrameType type : QuicFrameType.values()) {
            if (type == UNKNOWN) {
                continue;
            }
            MAP.put(type.value, type);
        }
    }

    public static QuicFrameType getFrameType(long value) {
        return MAP.getOrDefault(value, UNKNOWN);
    }

    public long getValue() {
        return value;
    }

    public String getName() {
        return this.name();
    }
}
