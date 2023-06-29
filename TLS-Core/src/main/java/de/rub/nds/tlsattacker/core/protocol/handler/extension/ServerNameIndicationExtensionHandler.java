/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNameIndicationExtensionHandler
        extends ExtensionHandler<ServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerNameIndicationExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(ServerNameIndicationExtensionMessage message) {
        List<SNIEntry> sniEntryList = new LinkedList<>();
        for (ServerNamePair pair : message.getServerNameList()) {
            NameType type = NameType.getNameType(pair.getServerNameType().getValue());
            if (type != null) {
                sniEntryList.add(new SNIEntry(new String(pair.getServerName().getValue()), type));
            } else {
                LOGGER.warn("Unknown SNI Type:" + pair.getServerNameType().getValue());
            }
        }
        tlsContext.setClientSNIEntryList(sniEntryList);
    }
}
