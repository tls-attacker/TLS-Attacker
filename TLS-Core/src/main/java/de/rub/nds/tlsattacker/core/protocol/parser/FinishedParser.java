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
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FinishedParser extends HandshakeMessageParser<FinishedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public FinishedParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(FinishedMessage msg) {
        LOGGER.debug("Parsing FinishedMessage");
        parseVerifyData(msg);
    }

    /**
     * Reads the next bytes as the VerifyData and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseVerifyData(FinishedMessage msg) {
        msg.setVerifyData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("VerifyData: {}", msg.getVerifyData().getValue());
    }
}
