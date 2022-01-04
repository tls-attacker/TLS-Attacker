/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.UserMappingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.UserMappingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UserMappingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserMappingExtensionHandler extends ExtensionHandler<UserMappingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserMappingExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public UserMappingExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new UserMappingExtensionParser(pointer, message, config);
    }

    @Override
    public UserMappingExtensionPreparator getPreparator(UserMappingExtensionMessage message) {
        return new UserMappingExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public UserMappingExtensionSerializer getSerializer(UserMappingExtensionMessage message) {
        return new UserMappingExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(UserMappingExtensionMessage message) {
        context.setUserMappingExtensionHintType(
            UserMappingExtensionHintType.getExtensionType(message.getUserMappingType().getValue()));
        LOGGER.debug("Adjusted the TLS context user mapping extension hint type to "
            + context.getUserMappingExtensionHintType().getValue());
    }

}
