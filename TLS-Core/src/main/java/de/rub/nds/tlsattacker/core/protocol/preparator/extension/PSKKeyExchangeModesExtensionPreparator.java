/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** RFC draft-ietf-tls-tls13-21 */
public class PSKKeyExchangeModesExtensionPreparator
        extends ExtensionPreparator<PSKKeyExchangeModesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PSKKeyExchangeModesExtensionMessage msg;

    public PSKKeyExchangeModesExtensionPreparator(
            Chooser chooser, PSKKeyExchangeModesExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing PSKKeyExchangeModesExtensionMessage");
        prepareListBytes();
        prepareListLength();
    }

    private void prepareListBytes() {
        if (msg.getKeyExchangeModesConfig() == null) {
            LOGGER.warn("No PSKKeyExchangeModes configured. Using empty byte[]");
            msg.setKeyExchangeModesListBytes(new byte[0]);
        } else {
            msg.setKeyExchangeModesListBytes(msg.getKeyExchangeModesConfig());
        }
    }

    private void prepareListLength() {
        msg.setKeyExchangeModesListLength(msg.getKeyExchangeModesListBytes().getValue().length);
    }
}
