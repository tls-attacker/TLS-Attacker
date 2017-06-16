/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNamePairSerializier;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerNameIndicationExtensionPreparator extends ExtensionPreparator<ServerNameIndicationExtensionMessage> {

    private final ServerNameIndicationExtensionMessage message;

    public ServerNameIndicationExtensionPreparator(Chooser chooser, ServerNameIndicationExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ServerNamePair pair : message.getServerNameList()) {
            ServerNamePairPreparator preparator = new ServerNamePairPreparator(chooser, pair);
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
