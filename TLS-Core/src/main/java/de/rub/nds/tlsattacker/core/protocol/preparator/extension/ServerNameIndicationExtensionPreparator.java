/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNamePairSerializier;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerNameIndicationExtensionPreparator extends ExtensionPreparator<ServerNameIndicationExtensionMessage> {

    private final ServerNameIndicationExtensionMessage message;

    public ServerNameIndicationExtensionPreparator(TlsContext context, ServerNameIndicationExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ServerNamePair pair : message.getServerNameList()) {
            ServerNamePairPreparator preparator = new ServerNamePairPreparator(context, pair);
            preparator.prepare();
            ServerNamePairSerializier serializer = new ServerNamePairSerializier(pair);
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] from ServerNamePair", ex);
            }
        }
        message.setServerNameListBytes(stream.toByteArray());
        message.setServerNameListLength(message.getServerNameListBytes().getValue().length);
    }

}
