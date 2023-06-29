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
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownExtensionParser extends ExtensionParser<UnknownExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    protected void parseExtensionData(UnknownExtensionMessage message) {
        message.setExtensionData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("ExtensionData: {}", message.getExtensionData().getValue());
        message.setDataConfig(message.getExtensionData().getValue());
    }

    @Override
    public void parse(UnknownExtensionMessage message) {
        parseExtensionData(message);
    }
}
