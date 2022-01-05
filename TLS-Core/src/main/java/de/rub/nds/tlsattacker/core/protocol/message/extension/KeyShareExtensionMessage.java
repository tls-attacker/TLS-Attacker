/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "KeyShareExtension")
public class KeyShareExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger keyShareListLength;

    @ModifiableVariableProperty
    private ModifiableByteArray keyShareListBytes;

    @HoldsModifiableVariable
    private List<KeyShareEntry> keyShareList;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean retryRequestMode;

    public KeyShareExtensionMessage() {
        super(ExtensionType.KEY_SHARE);
        keyShareList = new LinkedList<>();
    }

    public KeyShareExtensionMessage(Config tlsConfig) {
        super(ExtensionType.KEY_SHARE);
        keyShareList = new LinkedList<>();
        for (NamedGroup group : tlsConfig.getDefaultClientKeyShareNamedGroups()) {
            if (NamedGroup.getImplemented().contains(group)) {
                KeyShareEntry keyShareEntry = new KeyShareEntry(group, tlsConfig.getKeySharePrivate());
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

    public boolean isRetryRequestMode() {
        if (retryRequestMode == null || retryRequestMode.getValue() == null) {
            return false;
        }
        return retryRequestMode.getValue();
    }

    public void setRetryRequestMode(boolean retryRequestMode) {
        this.retryRequestMode = ModifiableVariableFactory.safelySetValue(this.retryRequestMode, retryRequestMode);
    }

    public void setRetryRequestMode(ModifiableBoolean retryRequestMode) {
        this.retryRequestMode = retryRequestMode;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> allModifiableVariableHolders = super.getAllModifiableVariableHolders();
        allModifiableVariableHolders.addAll(keyShareList);
        return allModifiableVariableHolders;
    }

}
