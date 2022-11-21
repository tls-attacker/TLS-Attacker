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
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserMappingExtensionParser extends ExtensionParser<UserMappingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserMappingExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(UserMappingExtensionMessage msg) {
        msg.setUserMappingType(parseByteField(ExtensionByteLength.USER_MAPPING_MAPPINGTYPE));
        LOGGER.debug("Parsed the user mapping extension with mapping hint type " + msg.getUserMappingType().getValue());
    }

    @Override
    protected UserMappingExtensionMessage createExtensionMessage() {
        return new UserMappingExtensionMessage();
    }

}
