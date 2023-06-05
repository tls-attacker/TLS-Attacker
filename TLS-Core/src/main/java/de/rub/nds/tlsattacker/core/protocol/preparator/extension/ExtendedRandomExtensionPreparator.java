/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class which prepares an Extended Random Extension Message for handshake messages, as defined as
 * in <a
 * href="https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02">draft-rescorla-tls-extended-random-02</a>
 */
public class ExtendedRandomExtensionPreparator
        extends ExtensionPreparator<ExtendedRandomExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExtendedRandomExtensionMessage message;

    public ExtendedRandomExtensionPreparator(
            Chooser chooser, ExtendedRandomExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        // Send specific extended Random based on current role in handshake
        if (chooser.getConnectionEndType().equals(ConnectionEndType.CLIENT)) {
            LOGGER.debug("Preparing Client Extended Random of Extended Random Extension Message.");
            message.setExtendedRandom(chooser.getClientExtendedRandom());
            LOGGER.debug(
                    "Prepared the Client Extended Random with value {}",
                    message.getExtendedRandom().getValue());
        }
        if (chooser.getConnectionEndType().equals(ConnectionEndType.SERVER)) {
            LOGGER.debug("Preparing Server Extended Random of Extended Random Extension Message.");
            if (!(chooser.getServerExtendedRandom().length
                    == chooser.getClientExtendedRandom().length)) {
                LOGGER.debug(
                        "Extended Random of Client is not same length as Default Server Extended Random."
                                + " Generating fresh Server Extended Random of appropriate length.");
                byte[] generatedExtendedRandom =
                        prepareExtendedRandom(chooser.getClientExtendedRandom().length);
                message.setExtendedRandom(generatedExtendedRandom);
            } else {
                message.setExtendedRandom(chooser.getServerExtendedRandom());
            }
            LOGGER.debug(
                    "Prepared the Server Extended Random with value {}",
                    message.getExtendedRandom().getValue());
        }
        prepareExtendedRandomLength(message);
    }

    private void prepareExtendedRandomLength(ExtendedRandomExtensionMessage msg) {
        msg.setExtendedRandomLength(msg.getExtendedRandom().getValue().length);
        LOGGER.debug("ExtendedRandomLength: " + msg.getExtendedRandomLength().getValue());
    }

    private byte[] prepareExtendedRandom(int length) {
        byte[] randomBytes = new byte[length];
        new Random().nextBytes(randomBytes);
        return randomBytes;
    }
}
