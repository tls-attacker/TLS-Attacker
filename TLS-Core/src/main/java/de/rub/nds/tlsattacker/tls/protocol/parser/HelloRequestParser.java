/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HelloRequestParser extends HandshakeMessageParser<HelloRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger(HelloRequestParser.class);

    public HelloRequestParser(int pointer, byte[] array) {
        super(pointer, array, HandshakeMessageType.HELLO_REQUEST);
    }

    @Override
    public HelloRequestMessage parse() {
        HelloRequestMessage message = new HelloRequestMessage();
        parseType(message);
        parseLength(message);
        if (message.getLength().getValue() != 0) {
            LOGGER.warn("Parsed HelloRequest with non-zero length! Not parsing payload.");
        }
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

}
