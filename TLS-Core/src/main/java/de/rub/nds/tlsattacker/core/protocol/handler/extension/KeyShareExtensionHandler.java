/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This handler processes the KeyShare extensions in ClientHello and ServerHello messages, as defined in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.7
 */
public class KeyShareExtensionHandler extends ExtensionHandler<KeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyShareExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(KeyShareExtensionMessage message) {
        if (message.isRetryRequestMode()) {
            adjustRetryRequestKeyShare(message);
        } else {
            List<KeyShareStoreEntry> ksEntryList = createKeyShareStoreEntries(message);
            if (context.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
                adjustServerKeyShareStore(ksEntryList);
            } else {
                context.setClientKeyShareStoreEntryList(ksEntryList);
            }
        }
    }

    private List<KeyShareStoreEntry> createKeyShareStoreEntries(KeyShareExtensionMessage message) {
        List<KeyShareStoreEntry> ksEntryList = new LinkedList<>();
        for (KeyShareEntry pair : message.getKeyShareList()) {
            NamedGroup type = NamedGroup.getNamedGroup(pair.getGroup().getValue());
            if (type != null) {
                if (pair.getPublicKey() != null && pair.getPublicKey().getValue() != null) {
                    ksEntryList.add(new KeyShareStoreEntry(type, pair.getPublicKey().getValue()));
                } else {
                    LOGGER.warn("Empty KeyShare - Setting only selected KeyShareType: to "
                        + ArrayConverter.bytesToHexString(pair.getGroup()));
                    context.setSelectedGroup(type);
                }
            } else {
                LOGGER.warn("Unknown KS Type:" + ArrayConverter.bytesToHexString(pair.getPublicKey().getValue()));
            }
        }
        return ksEntryList;
    }

    private void adjustServerKeyShareStore(List<KeyShareStoreEntry> ksEntryList) {
        // The server has only one key
        if (!ksEntryList.isEmpty()) {
            context.setServerKeyShareStoreEntry(
                new KeyShareStoreEntry(ksEntryList.get(0).getGroup(), ksEntryList.get(0).getPublicKey()));
            NamedGroup selectedGroup = context.getServerKeyShareStoreEntry().getGroup();
            LOGGER.debug("Setting selected NamedGroup in context to " + selectedGroup);
            context.setSelectedGroup(selectedGroup);
        }
    }

    private void adjustRetryRequestKeyShare(KeyShareExtensionMessage message) {
        if (!message.getKeyShareList().isEmpty()) {
            NamedGroup selectedGroup = message.getKeyShareList().get(0).getGroupConfig();
            LOGGER.debug("Setting selected NamedGroup from HelloRetryRequest in context to " + selectedGroup);
            context.setSelectedGroup(selectedGroup);
        }
    }
}
