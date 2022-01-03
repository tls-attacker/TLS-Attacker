/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareEntrySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareExtensionPreparator extends ExtensionPreparator<KeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

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
        if (msg.getKeyShareList() == null) {
            msg.setKeyShareList(new LinkedList<KeyShareEntry>());
        }
        stream = new ByteArrayOutputStream();

        if (msg.isRetryRequestMode()) {
            LOGGER.debug("Preparing KeyShareExtension with HelloRetryRequest structure");
            msg.setKeyShareList(setupRetryRequestKeyShareEntry());
        } else if (chooser.getTalkingConnectionEnd() == ConnectionEndType.SERVER) {
            LOGGER.debug("Preparing KeyShareExtension with ServerHello structure");
            msg.setKeyShareList(setupRegularServerKeyShareEntry());
        }

        if (!msg.isRetryRequestMode() && msg.getKeyShareList() != null) {
            prepareKeyShareEntries();
        }
    }

    private List<KeyShareEntry> setupRegularServerKeyShareEntry() {
        List<KeyShareEntry> serverList = new ArrayList<>();
        List<KeyShareStoreEntry> clientShares = chooser.getClientKeyShares();
        for (KeyShareStoreEntry i : clientShares) {
            if (chooser.getServerSupportedNamedGroups().contains(i.getGroup())) {
                KeyShareEntry predefinedServerKeyShare = getPredefinedKeyShareEntryFromMessage(i.getGroup());
                if (predefinedServerKeyShare != null) {
                    LOGGER.debug("Using predefined Key Share Entry for Server Hello");
                    serverList.add(predefinedServerKeyShare);
                } else {
                    KeyShareEntry keyShareEntry =
                        new KeyShareEntry(i.getGroup(), chooser.getConfig().getKeySharePrivate());
                    serverList.add(keyShareEntry);
                }
                break;
            }
        }
        if (serverList.isEmpty()) {
            LOGGER.debug("Client Key Share groups not supported - falling back to default selected group");
            KeyShareEntry keyShareEntry = new KeyShareEntry(chooser.getConfig().getDefaultSelectedNamedGroup(),
                chooser.getConfig().getKeySharePrivate());
            serverList.add(keyShareEntry);
        }
        return serverList;
    }

    private KeyShareEntry getPredefinedKeyShareEntryFromMessage(NamedGroup requiredGroup) {
        if (msg.getKeyShareList() != null) {
            for (KeyShareEntry entry : msg.getKeyShareList()) {
                if (entry.getGroupConfig() == requiredGroup) {
                    return entry;
                }
            }
        }
        return null;
    }

    private List<KeyShareEntry> setupRetryRequestKeyShareEntry() {
        List<KeyShareEntry> serverList = new ArrayList<>();
        NamedGroup preferredGroup = chooser.getConfig().getDefaultSelectedNamedGroup();
        KeyShareEntry emptyEntry = new KeyShareEntry();
        emptyEntry.setGroup(preferredGroup.getValue());
        emptyEntry.setGroupConfig(preferredGroup);
        serverList.add(emptyEntry);
        msg.setKeyShareListBytes(preferredGroup.getValue());
        return serverList;
    }

    private void prepareKeyShareEntries() {
        for (KeyShareEntry entry : msg.getKeyShareList()) {
            KeyShareEntryPreparator preparator = new KeyShareEntryPreparator(chooser, entry);
            preparator.prepare();
            KeyShareEntrySerializer serializer = new KeyShareEntrySerializer(entry);
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
