/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Random;

/**
 * Class which prepares an Extended Random Extension Message for handshake
 * messages, as defined as in
 * https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02
 */
public class ExtendedRandomExtensionPreparator extends ExtensionPreparator<ExtendedRandomExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExtendedRandomExtensionMessage message;

    public ExtendedRandomExtensionPreparator(Chooser chooser, ExtendedRandomExtensionMessage message,
            ExtendedRandomExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        // Send specific extended Random based on current role in handshake
        if (chooser.getConnectionEndType().equals(ConnectionEndType.CLIENT)) {
            LOGGER.debug("Offering Extended Random as Client.");
            message.setExtendedRandom(chooser.getClientExtendedRandom());
            LOGGER.debug("Prepared the Client Extended Random with value "
                    + ArrayConverter.bytesToHexString(message.getExtendedRandom().getValue()));
        }
        if (chooser.getConnectionEndType().equals(ConnectionEndType.SERVER)) {
            LOGGER.debug("Accepting Extended Random of Client.");
            if (!(chooser.getServerExtendedRandom().length == chooser.getClientExtendedRandom().length)) {
                LOGGER.debug("Extended Random of Client is not same length as Default Extended Random."
                        + "Generating fresh Extended Random of appropriate length.");
                byte[] generatedExtendedRandom = prepareExtendedRandom(chooser.getClientExtendedRandom().length);
                // Update Context with new Server extended Random
                LOGGER.debug("Updating Server Extended Random of current Context.");
                chooser.getContext().setServerExtendedRandom(generatedExtendedRandom);
                message.setExtendedRandom(generatedExtendedRandom);
            } else {
                message.setExtendedRandom(chooser.getServerExtendedRandom());
            }
            LOGGER.debug("Prepared the Server Extended Random with value "
                    + ArrayConverter.bytesToHexString(message.getExtendedRandom().getValue()));
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
