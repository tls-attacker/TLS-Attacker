/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlertSerializer extends ProtocolMessageSerializer<AlertMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the AlertSerializer
     *
     * @param message Message that should be serialized
     */
    public AlertSerializer(AlertMessage message) {
        super(message);
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing AlertMessage");
        writeLevel();
        writeDescription();
        return getAlreadySerialized();
    }

    /** Writes the level of the AlertMessage into the final byte[] */
    private void writeLevel() {
        appendByte(message.getLevel().getValue());
        LOGGER.debug("Level: " + message.getLevel().getValue());
    }

    /** Writes the description of the AlertMessage into the final byte[] */
    private void writeDescription() {
        appendByte(message.getDescription().getValue());
        LOGGER.debug("Description: " + message.getDescription().getValue());
    }
}
