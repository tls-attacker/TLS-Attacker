/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;

public class ClientEsniInner extends ModifiableVariableHolder implements Serializable {

    @ModifiableVariableProperty
    private ModifiableByteArray clientNonce;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger serverNameListLength;

    @ModifiableVariableProperty
    private ModifiableByteArray serverNameListBytes;

    @ModifiableVariableProperty
    private ModifiableByteArray padding;

    @HoldsModifiableVariable
    private List<ServerNamePair> serverNameList;

    public ClientEsniInner() {
        this.serverNameList = new LinkedList<>();
    }

    public ModifiableByteArray getClientNonce() {
        return clientNonce;
    }

    public void setClientNonce(ModifiableByteArray clientNonce) {
        this.clientNonce = clientNonce;
    }

    public void setClientNonce(byte[] bytes) {
        this.clientNonce = ModifiableVariableFactory.safelySetValue(clientNonce, bytes);
    }

    public ModifiableByteArray getServerNameListBytes() {
        return serverNameListBytes;
    }

    public void setServerNameListBytes(ModifiableByteArray serverNameListBytes) {
        this.serverNameListBytes = serverNameListBytes;
    }

    public void setServerNameListBytes(byte[] bytes) {
        this.serverNameListBytes = ModifiableVariableFactory.safelySetValue(serverNameListBytes, bytes);
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setPadding(byte[] bytes) {
        this.padding = ModifiableVariableFactory.safelySetValue(padding, bytes);
    }

    public ModifiableInteger getServerNameListLength() {
        return serverNameListLength;
    }

    public void setServerNameListLength(ModifiableInteger serverNameListLength) {
        this.serverNameListLength = serverNameListLength;
    }

    public void setServerNameListLength(int length) {
        this.serverNameListLength = ModifiableVariableFactory.safelySetValue(serverNameListLength, length);
    }

    public List<ServerNamePair> getServerNameList() {
        return serverNameList;
    }

    public void setServerNameList(List<ServerNamePair> serverNamePairList) {
        this.serverNameList = serverNamePairList;
    }
}