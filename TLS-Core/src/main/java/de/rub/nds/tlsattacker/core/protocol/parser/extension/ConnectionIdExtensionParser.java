/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ConnectionIdExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionIdExtensionParser extends ExtensionParser<ConnectionIdExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ConnectionIdExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(ConnectionIdExtensionMessage connectionIdExtensionMessage) {
        LOGGER.debug("Parsing ConnectionIdExtensionMessage");
        parseConnectionIdLength(connectionIdExtensionMessage);
        parseConnectionId(connectionIdExtensionMessage);
    }

    private void parseConnectionIdLength(ConnectionIdExtensionMessage msg) {
        msg.setConnectionIdLength(parseIntField(ExtensionByteLength.CONNECTION_ID_LENGTH));
        LOGGER.debug("ConnectionId length: " + msg.getConnectionIdLength().getValue());
    }

    private void parseConnectionId(ConnectionIdExtensionMessage msg) {
        msg.setConnectionId(parseByteArrayField(msg.getConnectionIdLength().getValue()));
        LOGGER.debug("ConnectionId: {}", msg.getConnectionId().getValue());
    }
}
