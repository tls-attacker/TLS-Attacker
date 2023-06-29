/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HeartbeatByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HeartbeatMessageParser extends ProtocolMessageParser<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     */
    public HeartbeatMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(HeartbeatMessage message) {
        LOGGER.debug("Parsing HeartbeatMessage");
        parseHeartbeatMessageType(message);
        parsePayloadLength(message);
        parsePayload(message);
        parsePadding(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    /**
     * Reads the next bytes as the HeartbeatMessageType and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseHeartbeatMessageType(HeartbeatMessage msg) {
        msg.setHeartbeatMessageType(parseByteField(HeartbeatByteLength.TYPE));
        LOGGER.debug("HeartbeatMessageType: " + msg.getHeartbeatMessageType().getValue());
    }

    /**
     * Reads the next bytes as the PayloadLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parsePayloadLength(HeartbeatMessage msg) {
        msg.setPayloadLength(parseIntField(HeartbeatByteLength.PAYLOAD_LENGTH));
        LOGGER.debug("PayloadLength: " + msg.getPayloadLength().getValue());
    }

    /**
     * Reads the next bytes as the Payload and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parsePayload(HeartbeatMessage msg) {
        msg.setPayload(parseByteArrayField(msg.getPayloadLength().getValue()));
        LOGGER.debug("Payload: {}", msg.getPayload().getValue());
    }

    /**
     * Reads the next bytes as the Padding and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parsePadding(HeartbeatMessage msg) {
        msg.setPadding(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("Padding: {}", msg.getPadding().getValue());
    }
}
