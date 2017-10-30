/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PreSharedKeyExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PreSharedKeyExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PreSharedKeyExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author marcel
 */
public class PreSharedKeyExtensionHandler extends ExtensionHandler<PreSharedKeyExtensionMessage> {

    public PreSharedKeyExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        return new PreSharedKeyExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(PreSharedKeyExtensionMessage message) {
        return new PreSharedKeyExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ExtensionSerializer getSerializer(PreSharedKeyExtensionMessage message) {
        return new PreSharedKeyExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(PreSharedKeyExtensionMessage message) {
        //TODO
    }

}
