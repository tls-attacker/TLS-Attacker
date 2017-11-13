/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class EarlyDataExtensionParser extends ExtensionParser<EarlyDataExtensionMessage> {

    public EarlyDataExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(EarlyDataExtensionMessage msg) {
        LOGGER.debug("Parsing EarlyDataExtensionMessage");
        if(msg.getExtensionLength().getValue() > 0) 
        {
            parseMaxEarlyDataSize(msg);
        }
    }

    @Override
    protected EarlyDataExtensionMessage createExtensionMessage() {
        return new EarlyDataExtensionMessage();
    }
    
    private void parseMaxEarlyDataSize(EarlyDataExtensionMessage msg)
    {
        msg.setMaxEarlyDataSize(parseIntField(ExtensionByteLength.MAX_EARLY_DATA_SIZE_LENGTH));
        LOGGER.debug("MaxEarlyDataSize: " + msg.getMaxEarlyDataSize().getValue());
    }

}
