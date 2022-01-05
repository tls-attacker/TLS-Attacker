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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;

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

    public void setClientNonce(byte[] clientNonce) {
        this.clientNonce = ModifiableVariableFactory.safelySetValue(this.clientNonce, clientNonce);
    }

    public ModifiableByteArray getServerNameListBytes() {
        return serverNameListBytes;
    }

    public void setServerNameListBytes(ModifiableByteArray serverNameListBytes) {
        this.serverNameListBytes = serverNameListBytes;
    }

    public void setServerNameListBytes(byte[] serverNameListBytes) {
        this.serverNameListBytes =
            ModifiableVariableFactory.safelySetValue(this.serverNameListBytes, serverNameListBytes);
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public ModifiableInteger getServerNameListLength() {
        return serverNameListLength;
    }

    public void setServerNameListLength(ModifiableInteger serverNameListLength) {
        this.serverNameListLength = serverNameListLength;
    }

    public void setServerNameListLength(int serverNameListLength) {
        this.serverNameListLength =
            ModifiableVariableFactory.safelySetValue(this.serverNameListLength, serverNameListLength);
    }

    public List<ServerNamePair> getServerNameList() {
        return serverNameList;
    }

    public void setServerNameList(List<ServerNamePair> serverNamePairList) {
        this.serverNameList = serverNamePairList;
    }
}