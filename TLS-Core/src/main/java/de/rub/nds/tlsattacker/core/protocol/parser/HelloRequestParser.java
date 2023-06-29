/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloRequestParser extends HandshakeMessageParser<HelloRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param inputStream
     * @param tlsContext
     */
    public HelloRequestParser(InputStream inputStream, TlsContext tlsContext) {
        super(inputStream, tlsContext);
    }

    /**
     * Reads the next bytes as the HandshakeMessageContent and writes them in the message
     *
     * @param msg Message to write in
     */
    @Override
    public void parse(HelloRequestMessage msg) {
        LOGGER.debug("Parsing HelloRequestMessage");
        if (getBytesLeft() != 0) {
            LOGGER.warn("Parsed HelloRequest with non-zero length! Not parsing payload.");
        }
    }
}
