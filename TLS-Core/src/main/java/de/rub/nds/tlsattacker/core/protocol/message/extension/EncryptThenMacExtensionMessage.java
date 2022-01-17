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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptThenMacExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptThenMacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptThenMacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptThenMacExtensionSerializer;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * RFC7366
 */
@XmlRootElement(name = "EncryptThenMacExtension")
public class EncryptThenMacExtensionMessage extends ExtensionMessage<EncryptThenMacExtensionMessage> {

    public EncryptThenMacExtensionMessage() {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

    public EncryptThenMacExtensionMessage(Config configF) {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

    @Override
    public EncryptThenMacExtensionParser getParser(TlsContext context, InputStream stream) {
        return new EncryptThenMacExtensionParser(stream, context.getConfig());
    }

    @Override
    public EncryptThenMacExtensionPreparator getPreparator(TlsContext context) {
        return new EncryptThenMacExtensionPreparator(context.getChooser(), this, getSerializer(context));
    }

    @Override
    public EncryptThenMacExtensionSerializer getSerializer(TlsContext context) {
        return new EncryptThenMacExtensionSerializer(this);
    }

    @Override
    public EncryptThenMacExtensionHandler getHandler(TlsContext context) {
        return new EncryptThenMacExtensionHandler(context);
    }
}
