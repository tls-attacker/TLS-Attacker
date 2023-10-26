/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.KeyShareExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "KeyShareExtension")
public class KeyShareExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger keyShareListLength;

    @ModifiableVariableProperty private ModifiableByteArray keyShareListBytes;

    @HoldsModifiableVariable private List<KeyShareEntry> keyShareList;

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
                KeyShareEntry keyShareEntry =
                        new KeyShareEntry(group, tlsConfig.getKeySharePrivate());
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
        this.keyShareListLength =
                ModifiableVariableFactory.safelySetValue(keyShareListLength, length);
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
        this.retryRequestMode =
                ModifiableVariableFactory.safelySetValue(this.retryRequestMode, retryRequestMode);
    }

    public void setRetryRequestMode(ModifiableBoolean retryRequestMode) {
        this.retryRequestMode = retryRequestMode;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> allModifiableVariableHolders =
                super.getAllModifiableVariableHolders();
        allModifiableVariableHolders.addAll(keyShareList);
        return allModifiableVariableHolders;
    }

    @Override
    public KeyShareExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new KeyShareExtensionParser(stream, tlsContext);
    }

    @Override
    public KeyShareExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new KeyShareExtensionPreparator(
                tlsContext.getChooser(), this, getSerializer(tlsContext));
    }

    @Override
    public KeyShareExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new KeyShareExtensionSerializer(
                this, tlsContext.getChooser().getConnectionEndType());
    }

    @Override
    public KeyShareExtensionHandler getHandler(TlsContext tlsContext) {
        return new KeyShareExtensionHandler(tlsContext);
    }
}
