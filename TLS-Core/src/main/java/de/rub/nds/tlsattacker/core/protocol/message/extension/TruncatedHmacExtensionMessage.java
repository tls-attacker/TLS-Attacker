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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TruncatedHmacExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TruncatedHmacExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TruncatedHmacExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TruncatedHmacExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This is a binary extension, which means that no extension data is used. This extension is defined
 * in RFC6066
 */
@XmlRootElement(name = "TruncatedHmacExtension")
public class TruncatedHmacExtensionMessage extends ExtensionMessage<TruncatedHmacExtensionMessage> {

    public TruncatedHmacExtensionMessage() {
        super(ExtensionType.TRUNCATED_HMAC);
    }

    @Override
    public TruncatedHmacExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new TruncatedHmacExtensionParser(stream, tlsContext);
    }

    @Override
    public TruncatedHmacExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new TruncatedHmacExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public TruncatedHmacExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new TruncatedHmacExtensionSerializer(this);
    }

    @Override
    public TruncatedHmacExtensionHandler getHandler(TlsContext tlsContext) {
        return new TruncatedHmacExtensionHandler(tlsContext);
    }
}
