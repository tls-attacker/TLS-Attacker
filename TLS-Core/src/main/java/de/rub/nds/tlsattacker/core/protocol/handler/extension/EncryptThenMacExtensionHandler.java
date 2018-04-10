/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptThenMacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptThenMacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptThenMacExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class EncryptThenMacExtensionHandler extends ExtensionHandler<EncryptThenMacExtensionMessage> {

    public EncryptThenMacExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public EncryptThenMacExtensionParser getParser(byte[] message, int pointer) {
        return new EncryptThenMacExtensionParser(pointer, message);
    }

    @Override
    public EncryptThenMacExtensionPreparator getPreparator(EncryptThenMacExtensionMessage message) {
        return new EncryptThenMacExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public EncryptThenMacExtensionSerializer getSerializer(EncryptThenMacExtensionMessage message) {
        return new EncryptThenMacExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(EncryptThenMacExtensionMessage message) {

    }
}
