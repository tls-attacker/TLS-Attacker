/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CookieExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CookieExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CookieExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class CookieExtensionHandler extends ExtensionHandler<CookieExtensionMessage> {

    public CookieExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new CookieExtensionParser(pointer, message, config);
    }

    @Override
    public ExtensionPreparator getPreparator(CookieExtensionMessage message) {
        return new CookieExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ExtensionSerializer getSerializer(CookieExtensionMessage message) {
        return new CookieExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(CookieExtensionMessage message) {
        context.setExtensionCookie(message.getCookie().getValue());
    }

}
