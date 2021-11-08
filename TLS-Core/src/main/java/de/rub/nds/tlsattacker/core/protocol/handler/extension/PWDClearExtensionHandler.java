/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PWDClearExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PWDClearExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDClearExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

public class PWDClearExtensionHandler extends ExtensionHandler<PWDClearExtensionMessage> {

    public PWDClearExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(PWDClearExtensionMessage message) {
        context.setClientPWDUsername(message.getUsername().getValue());
    }

    @Override
    public PWDClearExtensionParser getParser(InputStream stream) {
        return new PWDClearExtensionParser(stream, context.getConfig());
    }

    @Override
    public PWDClearExtensionPreparator getPreparator(PWDClearExtensionMessage message) {
        return new PWDClearExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public PWDClearExtensionSerializer getSerializer(PWDClearExtensionMessage message) {
        return new PWDClearExtensionSerializer(message);
    }
}
