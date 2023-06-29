/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SRPExtensionPreparator extends ExtensionPreparator<SRPExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SRPExtensionMessage message;

    public SRPExtensionPreparator(Chooser chooser, SRPExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        message.setSrpIdentifier(chooser.getConfig().getSecureRemotePasswordExtensionIdentifier());
        LOGGER.debug(
                "Prepared the SRP Extension with user identifier {}",
                message.getSrpIdentifier().getValue());
        message.setSrpIdentifierLength(message.getSrpIdentifier().getValue().length);
        LOGGER.debug(
                "Prepared the SRP Extension with user identifier length "
                        + message.getSrpIdentifierLength().getValue());
    }
}
