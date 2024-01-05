/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants;

import java.util.HashMap;
import java.util.Map;

public enum QuicTransportParameterEntryTypes {
    /**
     * This parameter is the value of the Destination Connection ID field from the first Initial
     * packet sent by the client. This transport parameter is only sent by a server.
     */
    ORIGINAL_DESTINATION_CONNECTION_ID((byte) 0x00),
    /**
     * The maximum idle timeout is a value in milliseconds that is encoded as an integer. Idle
     * timeout is disabled when both endpoints omit this transport parameter or specify a value of
     * 0.
     */
    MAX_IDLE_TIMEOUT((byte) 0x01),
    /**
     * A stateless reset token is used in verifying a stateless reset; see Section 10.3. This
     * parameter is a sequence of 16 bytes. This transport parameter MUST NOT be sent by a client
     * but MAY be sent by a server. A server that does not send this transport parameter cannot use
     * stateless reset (Section 10.3) for the connection ID negotiated during the handshake.
     */
    STATELESS_RESET_TOKEN((byte) 0x02),
    /**
     * The maximum UDP payload size parameter is an integer value that limits the size of UDP
     * payloads that the endpoint is willing to receive. UDP datagrams with payloads larger than
     * this limit are not likely to be processed by the receiver.
     */
    MAX_UDP_PAYLOAD_SIZE((byte) 0x03),
    /**
     * The initial maximum data parameter is an integer value that contains the initial value for
     * the maximum amount of data that can be sent on the connection. This is equivalent to sending
     * a MAX_DATA (Section 19.9) for the connection immediately after completing the handshake.
     */
    INITIAL_MAX_DATA((byte) 0x04),
    /**
     * This parameter is an integer value specifying the initial flow control limit for locally
     * initiated bidirectional streams.
     */
    INITIAL_MAX_STREAM_DATA_BIDI_LOCAL((byte) 0x05),
    /**
     * This parameter is an integer value specifying the initial flow control limit for
     * peer-initiated bidirectional streams.
     */
    INITIAL_MAX_STREAM_DATA_BIDI_REMOTE((byte) 0x06),
    /**
     * This parameter is an integer value specifying the initial flow control limit for
     * peer-initiated bidirectional streams.
     */
    INITIAL_MAX_STREAM_DATA_UNI((byte) 0x07),
    /**
     * The initial maximum bidirectional streams parameter is an integer value that contains the
     * initial maximum number of bidirectional streams the endpoint that receives this transport
     * parameter is permitted to initiate.
     */
    INITIAL_MAX_STREAMS_BIDI((byte) 0x08),
    /**
     * The initial maximum unidirectional streams parameter is an integer value that contains the
     * initial maximum number of unidirectional streams the endpoint that receives this transport
     * parameter is permitted to initiate.
     */
    INITIAL_MAX_STREAMS_UNI((byte) 0x09),
    /**
     * The acknowledgment delay exponent is an integer value indicating an exponent used to decode
     * the ACK Delay field in the ACK frame (Section 19.3).
     */
    ACK_DELAY_EXPONENT((byte) 0x0a),
    /**
     * The maximum acknowledgment delay is an integer value indicating the maximum amount of time in
     * milliseconds by which the endpoint will delay sending acknowledgments.
     */
    MAX_ACK_DELAY((byte) 0x0b),
    /**
     * The disable active migration transport parameter is included if the endpoint does not support
     * active connection migration on the address being used during the handshake.
     */
    DISABLE_ACTIVE_MIGRATION((byte) 0x0c),
    /**
     * The server's preferred address is used to effect a change in server address at the end of the
     * handshake. This transport parameter is only sent by a server.
     */
    PREFERRED_ADDRESS((byte) 0x0d),
    /**
     * This is an integer value specifying the maximum number of connection IDs from the peer that
     * an endpoint is willing to store.
     */
    ACTIVE_CONNECTION_ID_LIMIT((byte) 0x0e),
    /**
     * This is the value that the endpoint included in the Source Connection ID field of the first
     * Initial packet it sends for the connection.
     */
    INITIAL_SOURCE_CONNECTION_ID((byte) 0x0f),
    /**
     * This is the value that the server included in the Source Connection ID field of a Retry
     * packet. This transport parameter is only sent by a server.
     */
    RETRY_SOURCE_CONNECTION_ID((byte) 0x10),
    MAX_DATAGRAM_FRAME_SIZE((byte) 0x20),
    GOOGLE((byte) 0x47),
    PROVISIONAL_PARAMETERS((byte) 0x31),
    UNKNOWN((byte) 0xff);

    private byte value;

    private static final Map<Byte, QuicTransportParameterEntryTypes> MAP;

    QuicTransportParameterEntryTypes(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (QuicTransportParameterEntryTypes c : QuicTransportParameterEntryTypes.values()) {
            MAP.put(c.value, c);
        }
    }

    public static QuicTransportParameterEntryTypes getParameterEntryType(byte value) {
        QuicTransportParameterEntryTypes type = MAP.get(value);
        if (type == null) {
            return UNKNOWN;
        }
        return type;
    }

    public byte getValue() {
        return value;
    }
}
