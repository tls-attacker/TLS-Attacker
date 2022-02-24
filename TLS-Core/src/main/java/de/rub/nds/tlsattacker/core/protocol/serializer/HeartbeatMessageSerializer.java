/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HeartbeatByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HeartbeatMessageSerializer extends ProtocolMessageSerializer<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the HeartbeatMessageSerializer
     *
     * @param message
     *                Message that should be serialized
     */
    public HeartbeatMessageSerializer(HeartbeatMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing HeartbeatMessage");
        writeHeartbeatMessageType();
        writePayloadLength();
        writePayload();
        writePadding();
        return getAlreadySerialized();
    }

    @Override
    protected byte[] serializeBytes() {
        return serializeProtocolMessageContent();
    }

    /**
     * Writes the HeartbeatMessageType of the HeartbeatMessage into the final byte[]
     */
    private void writeHeartbeatMessageType() {
        appendByte(message.getHeartbeatMessageType().getValue());
        LOGGER.debug("HeartbeatMessageType: " + message.getHeartbeatMessageType().getValue());
    }

    /**
     * Writes the PayloadLength of the HeartbeatMessage into the final byte[]
     */
    private void writePayloadLength() {
        appendInt(message.getPayloadLength().getValue(), HeartbeatByteLength.PAYLOAD_LENGTH);
        LOGGER.debug("PayloadLength: " + message.getPayloadLength().getValue());
    }

    /**
     * Writes the Payload of the HeartbeatMessage into the final byte[]
     */
    private void writePayload() {
        appendBytes(message.getPayload().getValue());
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(message.getPayload().getValue()));
    }

    /**
     * Writes the Padding of the HeartbeatMessage into the final byte[]
     */
    private void writePadding() {
        appendBytes(message.getPadding().getValue());
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(message.getPadding().getValue()));
    }

}
