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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CachedInfoExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CachedInfoExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class CachedInfoExtensionHandler extends ExtensionHandler<CachedInfoExtensionMessage> {

    public CachedInfoExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public CachedInfoExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new CachedInfoExtensionParser(pointer, message, config);
    }

    @Override
    public CachedInfoExtensionPreparator getPreparator(CachedInfoExtensionMessage message) {
        return new CachedInfoExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public CachedInfoExtensionSerializer getSerializer(CachedInfoExtensionMessage message) {
        return new CachedInfoExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(CachedInfoExtensionMessage message) {
        context.setCachedInfoExtensionObjects(message.getCachedInfo());
    }

}
