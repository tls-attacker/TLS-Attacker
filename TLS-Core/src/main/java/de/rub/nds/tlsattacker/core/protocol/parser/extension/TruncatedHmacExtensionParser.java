/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;

public class TruncatedHmacExtensionParser extends ExtensionParser<TruncatedHmacExtensionMessage> {

    public TruncatedHmacExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
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
