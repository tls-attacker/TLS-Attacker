/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PasswordSaltExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PasswordSaltExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PasswordSaltExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PasswordSaltExtensionHandler extends ExtensionHandler<PasswordSaltExtensionMessage> {
    public PasswordSaltExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(PasswordSaltExtensionMessage message) {
        context.setServerPWDSalt(message.getSalt().getValue());
    }

    @Override
    public PasswordSaltExtensionParser getParser(byte[] message, int pointer) {
        return new PasswordSaltExtensionParser(pointer, message);
    }

    @Override
    public PasswordSaltExtensionPreparator getPreparator(PasswordSaltExtensionMessage message) {
        return new PasswordSaltExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public PasswordSaltExtensionSerializer getSerializer(PasswordSaltExtensionMessage message) {
        return new PasswordSaltExtensionSerializer(message);
    }
}
