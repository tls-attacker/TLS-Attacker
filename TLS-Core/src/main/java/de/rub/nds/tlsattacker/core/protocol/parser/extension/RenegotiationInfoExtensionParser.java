/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class RenegotiationInfoExtensionParser extends ExtensionParser<RenegotiationInfoExtensionMessage> {

    public RenegotiationInfoExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(RenegotiationInfoExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The renegotiation info length shouldn't exceed 2 bytes as defined in RFC 5246. "
                    + "Length was " + msg.getExtensionLength().getValue());
        }
        msg.setRenegotiationInfo(parseByteArrayField(msg.getExtensionLength().getValue()));
    }

    @Override
    protected RenegotiationInfoExtensionMessage createExtensionMessage() {
        return new RenegotiationInfoExtensionMessage();
    }

}
