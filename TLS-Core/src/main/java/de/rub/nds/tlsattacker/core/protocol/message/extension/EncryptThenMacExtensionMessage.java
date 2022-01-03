/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptThenMacExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptThenMacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptThenMacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptThenMacExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

/**
 * RFC7366
 */
public class EncryptThenMacExtensionMessage extends ExtensionMessage<EncryptThenMacExtensionMessage> {

    public EncryptThenMacExtensionMessage() {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

    public EncryptThenMacExtensionMessage(Config configF) {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

    @Override
    public EncryptThenMacExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new EncryptThenMacExtensionParser(stream, tlsContext.getConfig());
    }

    @Override
    public EncryptThenMacExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new EncryptThenMacExtensionPreparator(tlsContext.getChooser(), this, getSerializer(tlsContext));
    }

    @Override
    public EncryptThenMacExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new EncryptThenMacExtensionSerializer(this);
    }

    @Override
    public EncryptThenMacExtensionHandler getHandler(TlsContext tlsContext) {
        return new EncryptThenMacExtensionHandler(tlsContext);
    }
}
