/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;

public class TruncatedHmacExtensionParser extends ExtensionParser<TruncatedHmacExtensionMessage> {

    public TruncatedHmacExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(TruncatedHmacExtensionMessage msg) {
        // nothing to parse here, it's a opt-in extension
    }

    @Override
    protected TruncatedHmacExtensionMessage createExtensionMessage() {
        return new TruncatedHmacExtensionMessage();
    }

}
