/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AlertSerializer extends ProtocolMessageSerializer<AlertMessage> {

    private final AlertMessage msg;

    /**
     * Constructor for the AlertSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public AlertSerializer(AlertMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        writeLevel(msg);
        writeDescription(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the level of the AlertMessage into the final byte[]
     */
    private void writeLevel(AlertMessage msg) {
        appendByte(msg.getLevel().getValue());
        LOGGER.debug("Level: " + msg.getLevel().getValue());
    }

    /**
     * Writes the description of the AlertMessage into the final byte[]
     */
    private void writeDescription(AlertMessage msg) {
        appendByte(msg.getDescription().getValue());
        LOGGER.debug("Description: " + msg.getDescription().getValue());
    }

}
