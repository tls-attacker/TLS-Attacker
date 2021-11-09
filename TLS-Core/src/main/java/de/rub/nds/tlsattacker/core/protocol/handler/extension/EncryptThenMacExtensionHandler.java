/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptThenMacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptThenMacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptThenMacExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

public class EncryptThenMacExtensionHandler extends ExtensionHandler<EncryptThenMacExtensionMessage> {

    public EncryptThenMacExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public EncryptThenMacExtensionParser getParser(InputStream stream) {
        return new EncryptThenMacExtensionParser(stream, context.getConfig());
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
