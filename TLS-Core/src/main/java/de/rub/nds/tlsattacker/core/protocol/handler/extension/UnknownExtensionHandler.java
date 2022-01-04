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
    public UnknownExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new UnknownExtensionParser(pointer, message, config);
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
