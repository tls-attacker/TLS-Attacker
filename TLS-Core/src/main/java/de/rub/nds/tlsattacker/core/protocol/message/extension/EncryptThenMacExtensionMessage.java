/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptThenMacExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptThenMacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptThenMacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptThenMacExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** RFC7366 */
@XmlRootElement(name = "EncryptThenMacExtension")
public class EncryptThenMacExtensionMessage
        extends ExtensionMessage<EncryptThenMacExtensionMessage> {

    public EncryptThenMacExtensionMessage() {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

    @Override
    public EncryptThenMacExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new EncryptThenMacExtensionParser(stream, tlsContext);
    }

    @Override
    public EncryptThenMacExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new EncryptThenMacExtensionPreparator(tlsContext.getChooser(), this);
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
