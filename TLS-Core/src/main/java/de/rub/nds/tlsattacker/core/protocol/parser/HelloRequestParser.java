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
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class HelloRequestParser extends HandshakeMessageParser<HelloRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param inputStream
     * @param tlsContext
     * @param version
     *                    Version of the Protocol
     */
    public HelloRequestParser(InputStream inputStream, ProtocolVersion version, TlsContext tlsContext) {
        super(inputStream, HandshakeMessageType.HELLO_REQUEST, version, tlsContext);
    }

    /**
     * Reads the next bytes as the HandshakeMessageContent and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    @Override
    protected void parseHandshakeMessageContent(HelloRequestMessage msg) {
        LOGGER.debug("Parsing HelloRequestMessage");
        if (getBytesLeft() != 0) {
            LOGGER.warn("Parsed HelloRequest with non-zero length! Not parsing payload.");
        }
    }
}
