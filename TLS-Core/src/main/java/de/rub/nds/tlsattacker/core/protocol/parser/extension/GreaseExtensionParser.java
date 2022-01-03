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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;

public class GreaseExtensionParser extends ExtensionParser<GreaseExtensionMessage> {
    public GreaseExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(GreaseExtensionMessage msg) {
        msg.setRandomData(parseByteArrayField(msg.getExtensionLength().getValue()));
        msg.setData(msg.getRandomData().getValue());
        msg.setType(ExtensionType.getExtensionType(msg.getExtensionType().getValue()));
    }

    @Override
    protected GreaseExtensionMessage createExtensionMessage() {
        return new GreaseExtensionMessage();
    }
}
