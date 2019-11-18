/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PasswordSaltExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PasswordSaltExtensionPreparator extends ExtensionPreparator<PasswordSaltExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PasswordSaltExtensionMessage msg;

    public PasswordSaltExtensionPreparator(Chooser chooser, PasswordSaltExtensionMessage message,
            PasswordSaltExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing PasswordSaltExtension");
        prepareSalt(msg);
        prepareSaltLength(msg);
    }

    private void prepareSalt(PasswordSaltExtensionMessage msg) {
        msg.setSalt(chooser.getConfig().getDefaultServerPWDSalt());
        LOGGER.debug("Salt: " + ArrayConverter.bytesToHexString(msg.getSalt()));
    }

    private void prepareSaltLength(PasswordSaltExtensionMessage msg) {
        msg.setSaltLength(msg.getSalt().getValue().length);
        LOGGER.debug("SaltLength: " + msg.getSaltLength().getValue());
    }
}
