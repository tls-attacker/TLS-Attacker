/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingExtensionHandler extends ExtensionHandler<PaddingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PaddingExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    /**
     * Adjusts the TLS context based on the length of the padding extension.
     *
     * @param message The message for which the context should be adjusted
     */
    @Override
    public void adjustTLSExtensionContext(PaddingExtensionMessage message) {
        tlsContext.setPaddingExtensionBytes(message.getPaddingBytes().getValue());
        LOGGER.debug(
                "The context PaddingExtension bytes were set to {}",
                tlsContext.getPaddingExtensionBytes());
    }
}
