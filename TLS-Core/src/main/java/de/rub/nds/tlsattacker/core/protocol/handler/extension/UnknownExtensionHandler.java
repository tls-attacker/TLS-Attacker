/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.UnknownExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.UnknownExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UnknownExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class UnknownExtensionHandler extends ExtensionHandler<UnknownExtensionMessage> {

    public UnknownExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(UnknownExtensionMessage message) {
    }

    @Override
    public UnknownExtensionParser getParser(byte[] message, int pointer) {
        return new UnknownExtensionParser(pointer, message);
    }

    @Override
    public UnknownExtensionPreparator getPreparator(UnknownExtensionMessage message) {
        return new UnknownExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public UnknownExtensionSerializer getSerializer(UnknownExtensionMessage message) {
        return new UnknownExtensionSerializer(message);
    }

}
