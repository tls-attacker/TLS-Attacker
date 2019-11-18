/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PWDClearExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PWDClearExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDClearExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PWDClearExtensionHandler extends ExtensionHandler<PWDClearExtensionMessage> {
    public PWDClearExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(PWDClearExtensionMessage message) {
        context.setClientPWDUsername(message.getUsername().getValue());
    }

    @Override
    public PWDClearExtensionParser getParser(byte[] message, int pointer) {
        return new PWDClearExtensionParser(pointer, message);
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
