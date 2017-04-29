/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownExtensionParser extends ExtensionParser<UnknownExtensionMessage> {

    public UnknownExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    protected void parseExtensionData(UnknownExtensionMessage message) {
        if (getBytesLeft() == 0) {
            // No bytes left for extension data
        } else if (getBytesLeft() < message.getExtensionLength().getValue()) {
            message.setExtensionData(parseByteArrayField(getBytesLeft()));
        } else {
            message.setExtensionData(parseByteArrayField(message.getExtensionLength().getValue()));
        }
    }

    @Override
    public void parseExtensionMessageContent(UnknownExtensionMessage message) {
        if (hasExtensionData(message)) {
            parseExtensionData(message);
        }
    }

    @Override
    protected UnknownExtensionMessage createExtensionMessage() {
        return new UnknownExtensionMessage();
    }
}
