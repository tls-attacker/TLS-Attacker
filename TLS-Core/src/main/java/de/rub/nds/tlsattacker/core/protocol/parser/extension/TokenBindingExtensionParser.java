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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TokenBindingExtensionParser extends ExtensionParser<TokenBindingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public TokenBindingExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(TokenBindingExtensionMessage msg) {
        msg.setTokenbindingVersion(parseByteArrayField(ExtensionByteLength.TOKENBINDING_VERSION));
        LOGGER.debug("The token binding extension parser parsed the version: "
                + msg.getTokenbindingVersion().toString());
        msg.setParameterListLength(parseByteField(ExtensionByteLength.TOKENBINDING_KEYPARAMETER_LENGTH));
        LOGGER.debug("The token binding extension parser parsed the KeyParameterLength : "
                + msg.getParameterListLength());
        msg.setTokenbindingKeyParameters(parseByteArrayField(msg.getParameterListLength().getValue()));
        LOGGER.debug("The token binding extension parser parsed the KeyParameters : "
                + msg.getTokenbindingKeyParameters().toString());
    }

    @Override
    protected TokenBindingExtensionMessage createExtensionMessage() {
        return new TokenBindingExtensionMessage();
    }

}
