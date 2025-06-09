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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownSSL2Message;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownSSL2MessageParser extends SSL2MessageParser<UnknownSSL2Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     */
    public UnknownSSL2MessageParser(InputStream stream, TlsContext context) {
        super(stream, context);
    }

    /**
     * Since we don't know what this is, we cannot make assumptions about length fields or the such,
     * so we assume that all data we received in the array is part of this unknown message
     */
    private void parseCompleteMessage(UnknownSSL2Message msg) {
        msg.setCompleteResultingMessage(parseByteArrayField(getBytesLeft()));
    }

    @Override
    public void parse(UnknownSSL2Message message) {
        LOGGER.debug("Parsing UnknownSSL2Message");
        parseCompleteMessage(message);
    }
}
