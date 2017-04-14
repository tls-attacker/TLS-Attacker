/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionParser extends ExtensionParser<PaddingExtensionMessage>{

    public PaddingExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(PaddingExtensionMessage msg) {
        msg.setExtensionLength(parseIntField(ExtensionByteLength.PADDING_LENGTH));
        msg.setExtensionBytes(parseByteArrayField(msg.getExtensionLength().getValue()));
    }

    @Override
    protected PaddingExtensionMessage createExtensionMessage() {
        return new PaddingExtensionMessage();
    }
    
    
}
