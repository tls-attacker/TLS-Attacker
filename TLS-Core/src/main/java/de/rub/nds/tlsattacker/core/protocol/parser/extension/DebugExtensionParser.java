/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.DebugExtensionMessage;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugExtensionParser extends ExtensionParser<DebugExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(DebugExtensionMessage debugExtensionMessage) {
        LOGGER.debug("Parsing DebugExtensionMessage");
        parseDebugContent(debugExtensionMessage);
    }

    private void parseDebugContent(DebugExtensionMessage msg) {
        msg.setDebugContent(
                new String(
                        parseByteArrayField(msg.getExtensionLength().getValue()),
                        StandardCharsets.ISO_8859_1));
        LOGGER.debug("Debug Content: {}", msg.getDebugContent().getValue());
    }
}
