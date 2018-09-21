/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RenegotiationInfoExtensionParser extends ExtensionParser<RenegotiationInfoExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RenegotiationInfoExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(RenegotiationInfoExtensionMessage msg) {
        msg.setRenegotiationInfoLength(parseIntField(ExtensionByteLength.RENEGOTIATION_INFO));
        if (msg.getRenegotiationInfoLength().getValue() > 255) {
            LOGGER.warn("The renegotiation info length shouldn't exceed 1 byte as defined in RFC 5246. "
                    + "Length was " + msg.getExtensionLength().getValue());
        }
        msg.setRenegotiationInfo(parseByteArrayField(msg.getRenegotiationInfoLength().getValue()));
        LOGGER.debug("The RenegotiationInfoExtensionParser parsed the value "
                + bytesToHexString(msg.getRenegotiationInfo()));
    }

    @Override
    protected RenegotiationInfoExtensionMessage createExtensionMessage() {
        return new RenegotiationInfoExtensionMessage();
    }

}
