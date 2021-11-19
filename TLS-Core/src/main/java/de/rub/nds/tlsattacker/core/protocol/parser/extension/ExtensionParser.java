/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 */
public abstract class ExtensionParser<Extension extends ExtensionMessage> extends Parser<Extension> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config config;

    public ExtensionParser(InputStream stream, Config config) {
        super(stream);
        this.config = config;
    }

    @Override
    public final void parse(Extension extension) {
        LOGGER.debug("Parsing ExtensionMessage");
        parseExtensionMessageContent(extension);
    }

    public abstract void parseExtensionMessageContent(Extension extension);

    /**
     * Checks if the Extension has ExtensionData specified
     *
     * @param  message
     *                 The message to check
     * @return         True if extension did specify Data in its length field
     */
    protected boolean hasExtensionData(ExtensionMessage message) {
        return message.getExtensionLength().getValue() > 0;
    }
}
