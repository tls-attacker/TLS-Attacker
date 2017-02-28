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
import de.rub.nds.tlsattacker.tls.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloDoneMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerHelloDoneParser extends HandshakeMessageParser<ServerHelloDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger(ServerHelloDoneParser.class);

    public ServerHelloDoneParser(int pointer, byte[] array) {
        super(pointer, array, HandshakeMessageType.SERVER_HELLO_DONE);
    }

    @Override
    public ServerHelloDoneMessage parse() {
        ServerHelloDoneMessage message = new ServerHelloDoneMessage();
        parseType(message);
        parseLength(message);
        if (message.getLength().getValue() != 0) {
            LOGGER.warn("Parsed ServerHelloDone with non-zero length! Not parsing payload.");
        }
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

}
