/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;

import java.util.LinkedList;
import java.util.List;

public class KeyShareExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger keyShareListLength;

    @ModifiableVariableProperty
    private ModifiableByteArray keyShareListBytes;

    @HoldsModifiableVariable
    private List<KeyShareEntry> keyShareList;

    public KeyShareExtensionMessage() {
        super(ExtensionType.KEY_SHARE);
    }

    public KeyShareExtensionMessage(Config tlsConfig) {
        super(ExtensionType.KEY_SHARE);
        keyShareList = new LinkedList<>();
        for (KeyShareStoreEntry storeEntry : tlsConfig.getDefaultClientKeyShareEntries()) {
            if (storeEntry.getGroup().isTls13()) {
                KeyShareEntry keyShareEntry = new KeyShareEntry(storeEntry.getGroup(), tlsConfig.getKeySharePrivate());
                keyShareList.add(keyShareEntry);
            }
        }
    }

    public ModifiableInteger getKeyShareListLength() {
        return keyShareListLength;
    }

    public void setKeyShareListLength(ModifiableInteger serverNameListLength) {
        this.keyShareListLength = serverNameListLength;
    }

    public void setKeyShareListLength(int length) {
        this.keyShareListLength = ModifiableVariableFactory.safelySetValue(keyShareListLength, length);
    }

    public ModifiableByteArray getKeyShareListBytes() {
        return keyShareListBytes;
    }

    public void setKeyShareListBytes(ModifiableByteArray serverNameListBytes) {
        this.keyShareListBytes = serverNameListBytes;
    }

    public void setKeyShareListBytes(byte[] bytes) {
        this.keyShareListBytes = ModifiableVariableFactory.safelySetValue(keyShareListBytes, bytes);
    }

    public List<KeyShareEntry> getKeyShareList() {
        return keyShareList;
    }

    public void setKeyShareList(List<KeyShareEntry> keyShareList) {
        this.keyShareList = keyShareList;
    }
}
