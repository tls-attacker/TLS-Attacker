/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.UserMappingExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class UserMappingExtensionPreparator extends ExtensionPreparator<UserMappingExtensionMessage> {

    private final UserMappingExtensionMessage msg;

    public UserMappingExtensionPreparator(TlsContext context, UserMappingExtensionMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setUserMappingType(context.getConfig().getUserMappingExtensionHintType().getValue());
        LOGGER.debug("Prepared the user mapping extension with hint type " + msg.getUserMappingType().getValue());
    }

}
