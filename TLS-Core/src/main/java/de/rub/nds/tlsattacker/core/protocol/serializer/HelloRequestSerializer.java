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
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloRequestSerializer extends HandshakeMessageSerializer<HelloRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the HelloRequestSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */
    public HelloRequestSerializer(HelloRequestMessage message, ProtocolVersion version) {
        super(message, version);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing HelloRequestMessage");
        return getAlreadySerialized();
    }

}
