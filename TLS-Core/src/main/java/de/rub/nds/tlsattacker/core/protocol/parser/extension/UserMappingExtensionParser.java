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
import de.rub.nds.tlsattacker.core.protocol.message.UserMappingExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class UserMappingExtensionParser extends ExtensionParser<UserMappingExtensionMessage> {

    public UserMappingExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(UserMappingExtensionMessage msg) {
        msg.setUserMappingType(parseByteField(ExtensionByteLength.USER_MAPPING_EXTENSION_MAPPINGTYPE_LENGTH));
        LOGGER.debug("Parsed the user mapping extension with mapping hint type " + msg.getUserMappingType().getValue());
    }

    @Override
    protected UserMappingExtensionMessage createExtensionMessage() {
        return new UserMappingExtensionMessage();
    }

}
