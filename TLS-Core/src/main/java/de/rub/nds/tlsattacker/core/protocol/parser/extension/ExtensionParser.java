/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

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
     * @return True if extension did specify Data in its length field
     */
    protected boolean hasExtensionData(ExtensionMessage message) {
        return getBytesLeft() > 0;
    }
}
