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
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.GreaseExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.GreaseExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.GreaseExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class GreaseExtensionHandler extends ExtensionHandler<GreaseExtensionMessage> {

    public GreaseExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public GreaseExtensionParser getParser(byte[] message, int pointer, Config config) {
        return null;
    }

    @Override
    public GreaseExtensionPreparator getPreparator(GreaseExtensionMessage message) {
        return new GreaseExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public GreaseExtensionSerializer getSerializer(GreaseExtensionMessage message) {
        return new GreaseExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(GreaseExtensionMessage message) {

    }
}
