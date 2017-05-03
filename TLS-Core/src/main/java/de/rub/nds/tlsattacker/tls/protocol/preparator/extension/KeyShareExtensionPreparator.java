/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.KeySharePairSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/*
 * @author Nurullah Erinola
 */
public class KeyShareExtensionPreparator extends ExtensionPreparator<KeyShareExtensionMessage> {

    private final KeyShareExtensionMessage message;

    public KeyShareExtensionPreparator(TlsContext context, KeyShareExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (KeySharePair pair : message.getKeyShareList()) {
            KeySharePairPreparator preparator = new KeySharePairPreparator(context, pair);
            preparator.prepare();
            KeySharePairSerializer serializer = new KeySharePairSerializer(pair);
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] from KeySharePair", ex);
            }
        }
        message.setKeyShareListBytes(stream.toByteArray());
        message.setKeyShareListLength(message.getKeyShareListBytes().getValue().length);
    }

}
