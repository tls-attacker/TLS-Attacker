/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HeartbeatByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HeartbeatMessageParser extends ProtocolMessageParser<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *            Position in the array where the ProtocolMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ProtocolMessageParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public HeartbeatMessageParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected HeartbeatMessage parseMessageContent() {
        LOGGER.debug("Parsing HeartbeatMessage");
        HeartbeatMessage msg = new HeartbeatMessage();
        parseHeartbeatMessageType(msg);
        parsePayloadLength(msg);
        parsePayload(msg);
        parsePadding(msg);
        return msg;
    }

    /**
     * Reads the next bytes as the HearbeatMessageType and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseHeartbeatMessageType(HeartbeatMessage msg) {
        msg.setHeartbeatMessageType(parseByteField(HeartbeatByteLength.TYPE));
        LOGGER.debug("HeartbeatMessageType: " + msg.getHeartbeatMessageType().getValue());
    }

    /**
     * Reads the next bytes as the PayloadLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePayloadLength(HeartbeatMessage msg) {
        msg.setPayloadLength(parseIntField(HeartbeatByteLength.PAYLOAD_LENGTH));
        LOGGER.debug("PayloadLength: " + msg.getPayloadLength().getValue());
    }

    /**
     * Reads the next bytes as the Payload and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePayload(HeartbeatMessage msg) {
        msg.setPayload(parseByteArrayField(msg.getPayloadLength().getValue()));
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(msg.getPayload().getValue()));
    }

    /**
     * Reads the next bytes as the Padding and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePadding(HeartbeatMessage msg) {
        msg.setPadding(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getPadding().getValue()));
    }

}
