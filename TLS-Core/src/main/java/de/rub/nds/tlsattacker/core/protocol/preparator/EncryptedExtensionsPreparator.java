/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedExtensionsPreparator extends HandshakeMessagePreparator<EncryptedExtensionsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final EncryptedExtensionsMessage msg;

    public EncryptedExtensionsPreparator(Chooser chooser, EncryptedExtensionsMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing EncryptedExtensionsMessage");
        prepareExtensions();
        prepareExtensionLength();
    }

}
