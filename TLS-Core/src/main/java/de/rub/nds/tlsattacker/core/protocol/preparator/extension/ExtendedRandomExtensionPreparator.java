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
 * Class which prepares an Extended Random Extension Message for handshake messages, as defined as
 * in https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02
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
            message.setExtendedRandom(chooser.getClientExtendedRandom());
            LOGGER.debug("Prepared the Client Extended Random with value "
                    + ArrayConverter.bytesToHexString(message.getExtendedRandom().getValue()));
        }
        if (chooser.getConnectionEndType().equals(ConnectionEndType.SERVER)) {
            if(!(chooser.getServerExtendedRandom().length == chooser.getClientExtendedRandom().length)){
                // mirror extended Random length of Client
                byte[] generatedExtendedRandom = generateExtendedRandom(chooser.getClientExtendedRandom().length);
                // Update Context with new Server extended Random
                chooser.getContext().setServerExtendedRandom(generatedExtendedRandom);
                message.setExtendedRandom(generatedExtendedRandom);
            } else {
                message.setExtendedRandom(chooser.getServerExtendedRandom());
            }
            LOGGER.debug("Prepared the Server Extended Random with value "
                    + ArrayConverter.bytesToHexString(message.getExtendedRandom().getValue()));
        }
    }

    private byte[] generateExtendedRandom(int length){
        byte[] randomBytes = new byte[length];
        new Random().nextBytes(randomBytes);
        return randomBytes;
    }
}
