/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class EarlyDataExtensionPreparator extends ExtensionPreparator<EarlyDataExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EarlyDataExtensionPreparator(Chooser chooser, EarlyDataExtensionMessage message,
            ExtensionSerializer<EarlyDataExtensionMessage> serializer) {
        super(chooser, message, serializer);
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing EarlyDataExtensionMessage");
        // Empty in 0-RTT-Messages
    }

}
