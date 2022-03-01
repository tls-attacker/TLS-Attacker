/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloDoneParser extends HandshakeMessageParser<ServerHelloDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                Version of the Protocol
     * @param tlsContext
     *                A Config used in the current tlsContext
     */
    public ServerHelloDoneParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, HandshakeMessageType.SERVER_HELLO_DONE, version, tlsContext);
    }

    @Override
    protected void parseHandshakeMessageContent(ServerHelloDoneMessage msg) {
        LOGGER.debug("Parsing ServerHelloDoneMessage");
        if (getBytesLeft() != 0) {
            LOGGER.warn("Parsed ServerHelloDone with non-zero length! Not parsing payload.");
        }
    }
}
