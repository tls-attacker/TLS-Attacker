/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEncryptedSni;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;

public class EncryptedServerNameIndicationExtensionMessage extends ExtensionMessage {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    private List<ServerNamePair> serverNameList;

    @ModifiableVariableProperty
    private ModifiableByteArray serverNameListBytes;

    @HoldsModifiableVariable
    private ClientEsniInner clientEsniInner;

    @ModifiableVariableProperty
    private ModifiableByteArray clientEsniInnerBytes;

    @HoldsModifiableVariable
    private ClientEncryptedSni clientEncryptedSni;

    @ModifiableVariableProperty
    private ModifiableByteArray clientEncryptedSniBytes;

    public EncryptedServerNameIndicationExtensionMessage() {
        super(ExtensionType.ENCRYPTED_SERVER_NAME_INDICATION);
        LOGGER.warn("EncryptedServerNameIndicationExtensionMessage called. - ESNI not implemented yet.");
    }

    public List<ServerNamePair> getServerNameList() {
        return serverNameList;
    }

    public void setServerNameList(List<ServerNamePair> serverNameList) {
        this.serverNameList = serverNameList;
    }

    public ModifiableByteArray getServerNameListBytes() {
        return serverNameListBytes;
    }

    public void setServerNameListBytes(ModifiableByteArray serverNameListBytes) {
        this.serverNameListBytes = serverNameListBytes;
    }

    public ClientEsniInner getClientEsniInner() {
        return clientEsniInner;
    }

    public void setClientEsniInner(ClientEsniInner clientEsniInner) {
        this.clientEsniInner = clientEsniInner;
    }

    public ModifiableByteArray getClientEsniInnerBytes() {
        return clientEsniInnerBytes;
    }

    public void setClientEsniInnerBytes(ModifiableByteArray clientEsniInnerBytes) {
        this.clientEsniInnerBytes = clientEsniInnerBytes;
    }

    public void setClientEsniInnerBytes(byte[] bytes) {
        this.clientEsniInnerBytes = ModifiableVariableFactory.safelySetValue(serverNameListBytes, bytes);
    }

    public ClientEncryptedSni getClientEncryptedSni() {
        return clientEncryptedSni;
    }

    public void setClientEncryptedSni(ClientEncryptedSni clientEncryptedSni) {
        this.clientEncryptedSni = clientEncryptedSni;
    }

    public ModifiableByteArray getClientEncryptedSniBytes() {
        return clientEncryptedSniBytes;
    }

    public void setClientEncryptedSniBytes(ModifiableByteArray clientEncryptedSniBytes) {
        this.clientEncryptedSniBytes = clientEncryptedSniBytes;
    }

    public void setClientEncryptedSniBytes(byte[] bytes) {
        this.clientEncryptedSniBytes = ModifiableVariableFactory.safelySetValue(serverNameListBytes, bytes);
    }

}
