/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HeartbeatByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HeartbeatMessageSerializer extends ProtocolMessageSerializer<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HeartbeatMessage msg;

    /**
     * Constructor for the HeartbeatMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public HeartbeatMessageSerializer(HeartbeatMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing HeartbeatMessage");
        writeHeartbeatMessageType(msg);
        writePayloadLength(msg);
        writePayload(msg);
        writePadding(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the HeartbeatMessageType of the HeartbeatMessage into the final
     * byte[]
     */
    private void writeHeartbeatMessageType(HeartbeatMessage msg) {
        appendByte(msg.getHeartbeatMessageType().getValue());
        LOGGER.debug("HeartbeatMessageType: " + msg.getHeartbeatMessageType().getValue());
    }

    /**
     * Writes the PayloadLength of the HeartbeatMessage into the final byte[]
     */
    private void writePayloadLength(HeartbeatMessage msg) {
        appendInt(msg.getPayloadLength().getValue(), HeartbeatByteLength.PAYLOAD_LENGTH);
        LOGGER.debug("PayloadLength: " + msg.getPayloadLength().getValue());
    }

    /**
     * Writes the Payload of the HeartbeatMessage into the final byte[]
     */
    private void writePayload(HeartbeatMessage msg) {
        appendBytes(msg.getPayload().getValue());
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(msg.getPayload().getValue()));
    }

    /**
     * Writes the Padding of the HeartbeatMessage into the final byte[]
     */
    private void writePadding(HeartbeatMessage msg) {
        appendBytes(msg.getPadding().getValue());
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getPadding().getValue()));
    }

}
