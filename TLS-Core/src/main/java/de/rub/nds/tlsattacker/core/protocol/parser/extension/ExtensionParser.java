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
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** */
public abstract class ExtensionParser<Extension extends ExtensionMessage>
        extends Parser<Extension> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final TlsContext tlsContext;

    public ExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream);
        this.tlsContext = tlsContext;
    }

    /**
     * Checks if the Extension has ExtensionData specified
     *
     * @param message The message to check
     * @return True if extension did specify Data in its length field
     */
    protected boolean hasExtensionData(ExtensionMessage message) {
        return getBytesLeft() > 0;
    }

    public TlsContext getTlsContext() {
        return tlsContext;
    }
}
