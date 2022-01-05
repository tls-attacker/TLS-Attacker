/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlertSerializer extends TlsMessageSerializer<AlertMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the AlertSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */
    public AlertSerializer(AlertMessage message, ProtocolVersion version) {
        super(message, version);
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing AlertMessage");
        writeLevel();
        writeDescription();
        return getAlreadySerialized();
    }

    /**
     * Writes the level of the AlertMessage into the final byte[]
     */
    private void writeLevel() {
        appendByte(message.getLevel().getValue());
        LOGGER.debug("Level: " + message.getLevel().getValue());
    }

    /**
     * Writes the description of the AlertMessage into the final byte[]
     */
    private void writeDescription() {
        appendByte(message.getDescription().getValue());
        LOGGER.debug("Description: " + message.getDescription().getValue());
    }

}
