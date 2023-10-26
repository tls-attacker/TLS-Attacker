/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.HashSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedExtensionsPreparator
        extends HandshakeMessagePreparator<EncryptedExtensionsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedExtensionsPreparator(Chooser chooser, EncryptedExtensionsMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing EncryptedExtensionsMessage");
        if (chooser.getConfig().isRespectClientProposedExtensions()
                && message.getExtensions() == null) {
            autoSelectExtensions(
                    chooser.getConfig(),
                    chooser.getContext().getTlsContext().getProposedExtensions(),
                    new HashSet<>());
        }
        prepareExtensions();
        prepareExtensionLength();
    }
}
