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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptThenMacExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptThenMacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptThenMacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptThenMacExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** RFC7366 */
@XmlRootElement(name = "EncryptThenMacExtension")
public class EncryptThenMacExtensionMessage extends ExtensionMessage {

    public EncryptThenMacExtensionMessage() {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

    @Override
    public EncryptThenMacExtensionParser getParser(Context context, InputStream stream) {
        return new EncryptThenMacExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public EncryptThenMacExtensionPreparator getPreparator(Context context) {
        return new EncryptThenMacExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public EncryptThenMacExtensionSerializer getSerializer(Context context) {
        return new EncryptThenMacExtensionSerializer(this);
    }

    @Override
    public EncryptThenMacExtensionHandler getHandler(Context context) {
        return new EncryptThenMacExtensionHandler(context.getTlsContext());
    }
}
