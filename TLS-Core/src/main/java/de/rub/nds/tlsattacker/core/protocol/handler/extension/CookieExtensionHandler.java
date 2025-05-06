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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CookieExtensionHandler extends ExtensionHandler<CookieExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CookieExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(CookieExtensionMessage message) {
        tlsContext.setExtensionCookie(message.getCookie().getValue());
        LOGGER.debug("Set ExtensionCookie in Context to {}", message.getCookie().getValue());
    }
}
