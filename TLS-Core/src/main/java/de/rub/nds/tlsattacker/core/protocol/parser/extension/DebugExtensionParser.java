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
import de.rub.nds.tlsattacker.core.protocol.message.extension.DebugExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugExtensionParser extends ExtensionParser<DebugExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(DebugExtensionMessage connectionIdExtensionMessage) {
        LOGGER.debug("Parsing ConnectionIdExtensionMessage");
        parseDebugContentLength(connectionIdExtensionMessage);
        parseDebugContent(connectionIdExtensionMessage);
    }

    private void parseDebugContentLength(DebugExtensionMessage msg) {
        msg.setDebugContentLength(parseIntField(ExtensionByteLength.CONNECTION_ID_LENGTH));
        LOGGER.debug("DebugContent length: " + msg.getDebugContentLength().getValue());
    }

    private void parseDebugContent(DebugExtensionMessage msg) {
        msg.setDebugContent(parseByteArrayField(msg.getDebugContentLength().getValue()));
        LOGGER.debug("DebugContent: {}", msg.getDebugContent().getValue());
    }
}
