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

public enum QuicTransportErrorCodes {

    /**
     * An endpoint uses this with CONNECTION_CLOSE to signal that the connection is being closed
     * abruptly in the absence of any error.
     */
    NO_ERROR((byte) 0x00),
    /** The endpoint encountered an internal error and cannot continue with the connection. */
    INTERNAL_ERROR((byte) 0x01),
    /** The server refused to accept a new connection. */
    CONNECTION_REFUSED((byte) 0x02),
    /**
     * An endpoint received more data than it permitted in its advertised data limits; see Section
     * 4.
     */
    FLOW_CONTROL_ERROR((byte) 0x03),
    /**
     * An endpoint received a frame for a stream identifier that exceeded its advertised stream
     * limit for the corresponding stream type.
     */
    STREAM_LIMIT_ERROR((byte) 0x04),
    /**
     * An endpoint received a frame for a stream that was not in a state that permitted that frame;
     * see Section 3.
     */
    STREAM_STATE_ERROR((byte) 0x05),
    /**
     * (1) An endpoint received a STREAM frame containing data that exceeded the previously
     * established final size, (2) an endpoint received a STREAM frame or a RESET_STREAM frame
     * containing a final size that was lower than the size of stream data that was already
     * received, or (3) an endpoint received a STREAM frame or a RESET_STREAM frame containing a
     * different final size to the one already established.
     */
    FINAL_SIZE_ERROR((byte) 0x06),
    /**
     * An endpoint received a frame that was badly formatted -- for instance, a frame of an unknown
     * type or an ACK frame that has more acknowledgment ranges than the remainder of the packet
     * could carry.
     */
    FRAME_ENCODING_ERROR((byte) 0x07),
    /**
     * An endpoint received transport parameters that were badly formatted, included an invalid
     * value, omitted a mandatory transport parameter, included a forbidden transport parameter, or
     * were otherwise in error.
     */
    TRANSPORT_PARAMETER_ERROR((byte) 0x08),
    /**
     * The number of connection IDs provided by the peer exceeds the advertised
     * active_connection_id_limit.
     */
    CONNECTION_ID_LIMIT_ERROR((byte) 0x09),
    /**
     * An endpoint detected an error with protocol compliance that was not covered by more specific
     * error codes.
     */
    PROTOCOL_VIOLATION((byte) 0x0a),
    /** A server received a client Initial that contained an invalid Token field. */
    INVALID_TOKEN((byte) 0x0b),
    /** The application or application protocol caused the connection to be closed. */
    APPLICATION_ERROR((byte) 0x0c),
    /** An endpoint has received more data in CRYPTO frames than it can buffer. */
    CRYPTO_BUFFER_EXCEEDED((byte) 0x0d),
    /** An endpoint detected errors in performing key updates; see Section 6 of [QUIC-TLS]. */
    KEY_UPDATE_ERROR((byte) 0x0e),
    /**
     * An endpoint has reached the confidentiality or integrity limit for the AEAD algorithm used by
     * the given connection.
     */
    AEAD_LIMIT_REACHED((byte) 0x0f),
    /**
     * An endpoint has determined that the network path is incapable of supporting QUIC. An endpoint
     * is unlikely to receive a CONNECTION_CLOSE frame carrying this code except when the path does
     * not support a large enough MTU.
     */
    NO_VIABLE_PATH((byte) 0x10),
    /**
     * The cryptographic handshake failed. A range of 256 values is reserved for carrying error
     * codes specific to the cryptographic handshake that is used. Codes for errors occurring when
     * TLS is used for the cryptographic handshake are described in Section 4.8 of [QUIC-TLS].
     */
    CRYPTO_ERROR((byte) 0x0100);

    private final int value;

    private static final Map<Byte, QuicTransportErrorCodes> MAP;

    QuicTransportErrorCodes(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (QuicTransportErrorCodes code : QuicTransportErrorCodes.values()) {
            MAP.put((byte) code.value, code);
        }
    }

    public static QuicTransportErrorCodes getErrorCode(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return (byte) value;
    }

    public String getName() {
        return this.name();
    }
}
