/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import java.io.InputStream;

public class GreaseExtensionParser extends ExtensionParser<GreaseExtensionMessage> {

    public GreaseExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(GreaseExtensionMessage msg) {
        msg.setRandomData(parseByteArrayField(getBytesLeft()));
        msg.setData(msg.getRandomData().getValue());
    }
}
