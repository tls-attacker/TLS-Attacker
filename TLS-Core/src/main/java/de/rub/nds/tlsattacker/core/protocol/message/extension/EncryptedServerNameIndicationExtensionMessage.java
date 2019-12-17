/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.EncryptedSniComputation;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;

public class EncryptedServerNameIndicationExtensionMessage extends ExtensionMessage {

    private static final Logger LOGGER = LogManager.getLogger();

    @ModifiableVariableProperty
    private ModifiableByteArray cipherSuite;

    @HoldsModifiableVariable
    private KeyShareEntry keyShareEntry;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger recordDigestLength;

    @ModifiableVariableProperty
    private ModifiableByteArray recordDigest;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger encryptedSniLength;

    @ModifiableVariableProperty
    private ModifiableByteArray encryptedSni;

    @HoldsModifiableVariable
    private ClientEsniInner clientEsniInner;

    @ModifiableVariableProperty
    private ModifiableByteArray clientEsniInnerBytes;

    @HoldsModifiableVariable
    private EncryptedSniComputation encryptedSniComputation;

    @ModifiableVariableProperty
    private ModifiableByteArray serverEsniNonce;

    public EncryptedServerNameIndicationExtensionMessage() {
        super(ExtensionType.ENCRYPTED_SERVER_NAME_INDICATION);
        this.keyShareEntry = new KeyShareEntry();
        this.clientEsniInner = new ClientEsniInner();
        this.encryptedSniComputation = new EncryptedSniComputation();
    }

    public ModifiableByteArray getCipherSuite() {
        return cipherSuite;
    }

    public void setCipherSuite(ModifiableByteArray suite) {
        this.cipherSuite = suite;
    }

    public void setCipherSuite(byte[] bytes) {
        this.cipherSuite = ModifiableVariableFactory.safelySetValue(cipherSuite, bytes);
    }

    public KeyShareEntry getKeyShareEntry() {
        return keyShareEntry;
    }

    public void setKeyShareEntry(KeyShareEntry keyShareEntry) {
        this.keyShareEntry = keyShareEntry;
    }

    public ModifiableInteger getRecordDigestLength() {
        return recordDigestLength;
    }

    public void setRecordDigestLength(ModifiableInteger recordDigestLength) {
        this.recordDigestLength = recordDigestLength;
    }

    public void setRecordDigestLength(int length) {
        this.recordDigestLength = ModifiableVariableFactory.safelySetValue(recordDigestLength, length);
    }

    public ModifiableByteArray getRecordDigest() {
        return recordDigest;
    }

    public void setRecordDigest(ModifiableByteArray recordDigest) {
        this.recordDigest = recordDigest;
    }

    public void setRecordDigest(byte[] bytes) {
        this.recordDigest = ModifiableVariableFactory.safelySetValue(recordDigest, bytes);
    }

    public ModifiableInteger getEncryptedSniLength() {
        return encryptedSniLength;
    }

    public void setEncryptedSniLength(ModifiableInteger encryptedSniLength) {
        this.encryptedSniLength = encryptedSniLength;
    }

    public void setEncryptedSniLength(int length) {
        this.encryptedSniLength = ModifiableVariableFactory.safelySetValue(encryptedSniLength, length);
    }

    public ModifiableByteArray getEncryptedSni() {
        return encryptedSni;
    }

    public void setEncryptedSni(ModifiableByteArray encryptedSni) {
        this.encryptedSni = encryptedSni;
    }

    public void setEncryptedSni(byte[] bytes) {
        this.encryptedSni = ModifiableVariableFactory.safelySetValue(encryptedSni, bytes);
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
        this.clientEsniInnerBytes = ModifiableVariableFactory.safelySetValue(clientEsniInnerBytes, bytes);
    }

    public EncryptedSniComputation getEncryptedSniComputation() {
        return encryptedSniComputation;
    }

    public void setEncryptedSniComputation(EncryptedSniComputation encryptedSniComputation) {
        this.encryptedSniComputation = encryptedSniComputation;
    }

    public ModifiableByteArray getServerEsniNonce() {
        return serverEsniNonce;
    }

    public void setServerEsniNonce(ModifiableByteArray serverEsniNonce) {
        this.serverEsniNonce = serverEsniNonce;
    }

    public void setServerEsniNonce(byte[] bytes) {
        this.serverEsniNonce = ModifiableVariableFactory.safelySetValue(serverEsniNonce, bytes);
    }
}