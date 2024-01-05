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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SRPExtensionHandler extends ExtensionHandler<SRPExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SRPExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(SRPExtensionMessage message) {
        tlsContext.setSecureRemotePasswordExtensionIdentifier(
                message.getSrpIdentifier().getValue());
        LOGGER.debug(
                "Adjusted the TLSContext secure remote password extension identifier to {}",
                tlsContext.getSecureRemotePasswordExtensionIdentifier());
    }
}
