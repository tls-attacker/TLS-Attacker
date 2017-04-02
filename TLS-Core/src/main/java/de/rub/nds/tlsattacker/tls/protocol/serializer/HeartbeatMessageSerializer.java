/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HeartbeatByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatMessageSerializer extends ProtocolMessageSerializer<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private final HeartbeatMessage msg;

    public HeartbeatMessageSerializer(HeartbeatMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        serializeHeartbeatMessageType(msg);
        serializePayloadLength(msg);
        serializePayload(msg);
        serializePadding(msg);
        return getAlreadySerialized();
    }

    private void serializeHeartbeatMessageType(HeartbeatMessage msg) {
        appendByte(msg.getHeartbeatMessageType().getValue());
        LOGGER.debug("HeartbeatMessageType: "+ msg.getHeartbeatMessageType().getValue());
    }

    private void serializePayloadLength(HeartbeatMessage msg) {
        appendInt(msg.getPayloadLength().getValue(), HeartbeatByteLength.PAYLOAD_LENGTH);
        LOGGER.debug("PayloadLength: "+ msg.getPayloadLength().getValue());
    }

    private void serializePayload(HeartbeatMessage msg) {
        appendBytes(msg.getPayload().getValue());
        LOGGER.debug("Payload: "+ Arrays.toString(msg.getPayload().getValue()));
    }

    private void serializePadding(HeartbeatMessage msg) {
        appendBytes(msg.getPadding().getValue());
        LOGGER.debug("Padding: "+ Arrays.toString(msg.getPadding().getValue())
        );
    }

}
