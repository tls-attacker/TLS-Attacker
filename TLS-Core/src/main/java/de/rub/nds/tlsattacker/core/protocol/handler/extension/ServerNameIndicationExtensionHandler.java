/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.SNIEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerNameIndicationExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerNameIndicationExtensionHandler extends ExtensionHandler<ServerNameIndicationExtensionMessage> {

    public ServerNameIndicationExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSContext(ServerNameIndicationExtensionMessage message) {
        List<SNIEntry> sniEntryList = new LinkedList<>();
        for (ServerNamePair pair : message.getServerNameList()) {
            NameType type = NameType.getNameType(pair.getServerNameType().getValue());
            if (type != null) {
                sniEntryList.add(new SNIEntry(new String(pair.getServerName().getValue()), type));
            } else {
                LOGGER.warn("Unknown SNI Type:" + pair.getServerNameType().getValue());
            }
        }
        context.setClientSNIEntryList(sniEntryList);
    }

    @Override
    public ServerNameIndicationExtensionParser getParser(byte[] message, int pointer) {
        return new ServerNameIndicationExtensionParser(pointer, message);
    }

    @Override
    public ServerNameIndicationExtensionPreparator getPreparator(ServerNameIndicationExtensionMessage message) {
        return new ServerNameIndicationExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ServerNameIndicationExtensionSerializer getSerializer(ServerNameIndicationExtensionMessage message) {
        return new ServerNameIndicationExtensionSerializer(message);
    }
}
