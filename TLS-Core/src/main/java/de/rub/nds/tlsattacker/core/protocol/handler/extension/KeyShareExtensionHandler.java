/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This handler processes the KeyShare extensions in ClientHello and ServerHello
 * messages, as defined in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.7
 */
public class KeyShareExtensionHandler extends ExtensionHandler<KeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ExtensionType type;

    public KeyShareExtensionHandler(TlsContext context, ExtensionType type) {
        super(context);
        if (type != ExtensionType.KEY_SHARE && type != ExtensionType.KEY_SHARE_OLD) {
            throw new RuntimeException("Trying to initalize KeyShareExtensionHandler with an illegal ExtensionType");
        }
        this.type = type;
    }

    @Override
    public KeyShareExtensionParser getParser(byte[] message, int pointer) {
        return new KeyShareExtensionParser(pointer, message, type);
    }

    @Override
    public KeyShareExtensionPreparator getPreparator(KeyShareExtensionMessage message) {
        return new KeyShareExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public KeyShareExtensionSerializer getSerializer(KeyShareExtensionMessage message) {
        return new KeyShareExtensionSerializer(message, context.getChooser().getConnectionEndType());
    }

    @Override
    public void adjustTLSExtensionContext(KeyShareExtensionMessage message) {
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
        if (context.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            // The server has only one key
            if (ksEntryList.size() > 0) {
                context.setServerKeyShareStoreEntry(new KeyShareStoreEntry(ksEntryList.get(0).getGroup(), ksEntryList
                        .get(0).getPublicKey()));
            }
        } else {
            context.setClientKeyShareStoreEntryList(ksEntryList);
        }
    }
}
