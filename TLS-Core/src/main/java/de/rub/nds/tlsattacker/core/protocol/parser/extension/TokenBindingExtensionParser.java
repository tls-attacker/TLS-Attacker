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
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionParser extends ExtensionParser<TokenBindingExtensionMessage> {

    public TokenBindingExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(TokenBindingExtensionMessage msg) {
        msg.setMajorTokenbindingVersion(parseByteField(ExtensionByteLength.TOKENBINDING_VERSION_LENGTH));
        LOGGER.debug("The token binding extension parser parsed the major version: "
                + msg.getMajorTokenbindingVersion().toString());
        msg.setMinorTokenbindingVersion(parseByteField(ExtensionByteLength.TOKENBINDING_VERSION_LENGTH));
        LOGGER.debug("The token binding extension parser parsed the minor version: "
                + msg.getMinorTokenbindingVersion().toString());
        msg.setParameterListLength(parseIntField(1));
        msg.setTokenbindingKeyParameters(parseByteArrayField(msg.getParameterListLength()));
        LOGGER.debug("The token binding extension parser parsed the KeyParameters : "
                + msg.getTokenbindingKeyParameters().toString());
    }

    @Override
    protected TokenBindingExtensionMessage createExtensionMessage() {
        LOGGER.debug("Created a new token binding extension message");
        return new TokenBindingExtensionMessage();
    }

}
