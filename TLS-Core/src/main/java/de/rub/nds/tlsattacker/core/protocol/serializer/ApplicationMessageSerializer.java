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
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ApplicationMessageSerializer extends ProtocolMessageSerializer<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the ApplicationMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public ApplicationMessageSerializer(ApplicationMessage message) {
        super(message);
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing ApplicationMessage");
        writeData();
        return getAlreadySerialized();
    }

    /** Writes the data of the ApplicationMessage into the final byte[] */
    private void writeData() {
        appendBytes(message.getData().getValue());
        LOGGER.debug("Data: {}", message.getData().getValue());
    }
}
