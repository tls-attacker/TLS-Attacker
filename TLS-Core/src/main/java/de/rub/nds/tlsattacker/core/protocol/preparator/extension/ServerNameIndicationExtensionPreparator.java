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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNamePairSerializier;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNameIndicationExtensionPreparator extends ExtensionPreparator<ServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerNameIndicationExtensionMessage msg;
    private ByteArrayOutputStream stream;

    public ServerNameIndicationExtensionPreparator(Chooser chooser, ServerNameIndicationExtensionMessage message,
            ServerNameIndicationExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing ServerNameIndicationExtensionMessage");
        stream = new ByteArrayOutputStream();
        for (ServerNamePair pair : msg.getServerNameList()) {
            ServerNamePairPreparator preparator = new ServerNamePairPreparator(chooser, pair);
            preparator.prepare();
            ServerNamePairSerializier serializer = new ServerNamePairSerializier(pair);
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] from ServerNamePair", ex);
            }
        }
        prepareServerNameListBytes(msg);
        prepareServerNameListLength(msg);
    }

    private void prepareServerNameListBytes(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListBytes(stream.toByteArray());
        LOGGER.debug("ServerNameListBytes: " + ArrayConverter.bytesToHexString(msg.getServerNameListBytes().getValue()));
    }

    private void prepareServerNameListLength(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListLength(msg.getServerNameListBytes().getValue().length);
        LOGGER.debug("ServerNameListLength: " + msg.getServerNameListLength().getValue());
    }

}
