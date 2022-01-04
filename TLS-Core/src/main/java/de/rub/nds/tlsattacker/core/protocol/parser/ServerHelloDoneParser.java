/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloDoneParser extends HandshakeMessageParser<ServerHelloDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *                Position in the array where the HandshakeMessageParser is supposed to start parsing
     * @param array
     *                The byte[] which the HandshakeMessageParser is supposed to parse
     * @param version
     *                Version of the Protocol
     * @param config
     *                A Config used in the current context
     */
    public ServerHelloDoneParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, HandshakeMessageType.SERVER_HELLO_DONE, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(ServerHelloDoneMessage msg) {
        LOGGER.debug("Parsing ServerHelloDoneMessage");
        if (msg.getLength().getValue() != 0) {
            LOGGER.warn("Parsed ServerHelloDone with non-zero length! Not parsing payload.");
        }
    }

    @Override
    protected ServerHelloDoneMessage createHandshakeMessage() {
        return new ServerHelloDoneMessage();
    }

}
