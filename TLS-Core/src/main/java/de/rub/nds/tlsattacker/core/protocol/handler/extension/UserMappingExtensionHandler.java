/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserMappingExtensionHandler extends ExtensionHandler<UserMappingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserMappingExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(UserMappingExtensionMessage message) {
        tlsContext.setUserMappingExtensionHintType(
                UserMappingExtensionHintType.getExtensionType(
                        message.getUserMappingType().getValue()));
        LOGGER.debug(
                "Adjusted the TLS context user mapping extension hint type to "
                        + tlsContext.getUserMappingExtensionHintType().getValue());
    }
}
