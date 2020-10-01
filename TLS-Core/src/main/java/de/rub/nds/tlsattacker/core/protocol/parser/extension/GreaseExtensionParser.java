/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;

public class GreaseExtensionParser extends ExtensionParser<GreaseExtensionMessage> {
    public GreaseExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(GreaseExtensionMessage msg) {
        parseByteArrayField(msg.getExtensionLength().getValue());
    }

    @Override
    protected GreaseExtensionMessage createExtensionMessage() {
        return new GreaseExtensionMessage();
    }
}
