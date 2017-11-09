/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TruncatedHmacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TruncatedHmacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TruncatedHmacExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class TruncatedHmacExtensionHandler extends ExtensionHandler<TruncatedHmacExtensionMessage> {

    public TruncatedHmacExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public TruncatedHmacExtensionParser getParser(byte[] message, int pointer) {
        return new TruncatedHmacExtensionParser(pointer, message);
    }

    @Override
    public TruncatedHmacExtensionPreparator getPreparator(TruncatedHmacExtensionMessage message) {
        return new TruncatedHmacExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public TruncatedHmacExtensionSerializer getSerializer(TruncatedHmacExtensionMessage message) {
        return new TruncatedHmacExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(TruncatedHmacExtensionMessage message) {
    }

}
