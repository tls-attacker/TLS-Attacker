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
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeySharePairSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class KeyShareExtensionPreparator extends ExtensionPreparator<KeyShareExtensionMessage> {

    private final KeyShareExtensionMessage msg;
    private ByteArrayOutputStream stream;

    public KeyShareExtensionPreparator(Chooser chooser, KeyShareExtensionMessage message,
            KeyShareExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing KeyShareExtensionMessage");
        stream = new ByteArrayOutputStream();
        for (KeySharePair pair : msg.getKeyShareList()) {
            KeySharePairPreparator preparator = new KeySharePairPreparator(chooser, pair);
            preparator.prepare();
            KeySharePairSerializer serializer = new KeySharePairSerializer(pair);
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] from KeySharePair", ex);
            }
        }
        prepareKeyShareListBytes(msg);
        prepareKeyShareListLength(msg);
    }

    private void prepareKeyShareListBytes(KeyShareExtensionMessage msg) {
        msg.setKeyShareListBytes(stream.toByteArray());
        LOGGER.debug("KeyShareListBytes: " + ArrayConverter.bytesToHexString(msg.getKeyShareListBytes().getValue()));
    }

    private void prepareKeyShareListLength(KeyShareExtensionMessage msg) {
        msg.setKeyShareListLength(msg.getKeyShareListBytes().getValue().length);
        LOGGER.debug("KeyShareListBytesLength: " + msg.getKeyShareListLength().getValue());
    }

}
