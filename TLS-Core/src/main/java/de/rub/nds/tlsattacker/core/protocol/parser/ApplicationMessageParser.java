/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ApplicationMessageParser extends ProtocolMessageParser<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     */
    public ApplicationMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageContent(ApplicationMessage message) {
        LOGGER.debug("Parsing ApplicationMessage");
        parseData(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    /**
     * Reads the next bytes as the Data and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseData(ApplicationMessage msg) {
        msg.setData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("Data: " + ArrayConverter.bytesToHexString(msg.getData().getValue()));
    }

}
