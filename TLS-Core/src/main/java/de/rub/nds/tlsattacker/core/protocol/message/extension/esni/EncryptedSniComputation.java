/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.esni;

import java.io.Serializable;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;

public class EncryptedSniComputation extends ModifiableVariableHolder {

    @ModifiableVariableProperty
    private ModifiableByteArray clientHelloRandom;

    @ModifiableVariableProperty
    private ModifiableByteArray esniContents;

    @ModifiableVariableProperty
    private ModifiableByteArray recordBytes;

    @ModifiableVariableProperty
    private ModifiableByteArray clientHelloKeyShare;

    @ModifiableVariableProperty
    private ModifiableByteArray serverPublicKey;

    @ModifiableVariableProperty
    private ModifiableByteArray esniContentsHash;

    @ModifiableVariableProperty
    private ModifiableByteArray esniSharedSecret;

    @ModifiableVariableProperty
    private ModifiableByteArray esniMasterSecret;

    @ModifiableVariableProperty
    private ModifiableByteArray key;

    @ModifiableVariableProperty
    private ModifiableByteArray iv;

    public ModifiableByteArray getClientHelloRandom() {
        return clientHelloRandom;
    }

    public void setClientHelloRandom(ModifiableByteArray clientHelloRandom) {
        this.clientHelloRandom = clientHelloRandom;
    }

    public void setClientHelloRandom(byte[] bytes) {
        this.clientHelloRandom = ModifiableVariableFactory.safelySetValue(clientHelloRandom, bytes);
    }

    public ModifiableByteArray getEsniContents() {
        return esniContents;
    }

    public void setEsniContents(ModifiableByteArray esniContents) {
        this.esniContents = esniContents;
    }

    public void setEsniContents(byte[] bytes) {
        this.esniContents = ModifiableVariableFactory.safelySetValue(esniContents, bytes);
    }

    public ModifiableByteArray getRecordBytes() {
        return recordBytes;
    }

    public void setRecordBytes(ModifiableByteArray recordBytes) {
        this.recordBytes = recordBytes;
    }

    public void setRecordBytes(byte[] bytes) {
        this.recordBytes = ModifiableVariableFactory.safelySetValue(recordBytes, bytes);
    }

    public ModifiableByteArray getClientHelloKeyShare() {
        return clientHelloKeyShare;
    }

    public void setClientHelloKeyShare(ModifiableByteArray clientHelloKeyShare) {
        this.clientHelloKeyShare = clientHelloKeyShare;
    }

    public void setClientHelloKeyShare(byte[] bytes) {
        this.clientHelloKeyShare = ModifiableVariableFactory.safelySetValue(clientHelloKeyShare, bytes);
    }

    public ModifiableByteArray getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(ModifiableByteArray pk) {
        this.serverPublicKey = pk;
    }

    public void setServerPublicKey(byte[] bytes) {
        this.serverPublicKey = ModifiableVariableFactory.safelySetValue(serverPublicKey, bytes);
    }

    public ModifiableByteArray getEsniContentsHash() {
        return esniContentsHash;
    }

    public void setEsniContentsHash(ModifiableByteArray esniContentsHash) {
        this.esniContentsHash = esniContentsHash;
    }

    public void setEsniContentsHash(byte[] bytes) {
        this.esniContentsHash = ModifiableVariableFactory.safelySetValue(esniContentsHash, bytes);
    }

    public ModifiableByteArray getEsniSharedSecret() {
        return esniSharedSecret;
    }

    public void setEsniSharedSecret(ModifiableByteArray esniSharedSecret) {
        this.esniSharedSecret = esniSharedSecret;
    }

    public void setEsniSharedSecret(byte[] bytes) {
        this.esniSharedSecret = ModifiableVariableFactory.safelySetValue(esniSharedSecret, bytes);
    }

    public ModifiableByteArray getEsniMasterSecret() {
        return esniMasterSecret;
    }

    public void setEsniMasterSecret(ModifiableByteArray esniMasterSecret) {
        this.esniMasterSecret = esniMasterSecret;
    }

    public void setEsniMasterSecret(byte[] bytes) {
        this.esniMasterSecret = ModifiableVariableFactory.safelySetValue(esniMasterSecret, bytes);
    }

    public ModifiableByteArray getKey() {
        return key;
    }

    public void setKey(ModifiableByteArray key) {
        this.key = key;
    }

    public void setKey(byte[] bytes) {
        this.key = ModifiableVariableFactory.safelySetValue(key, bytes);
    }

    public ModifiableByteArray getIv() {
        return iv;
    }

    public void setIv(ModifiableByteArray iv) {
        this.iv = iv;
    }

    public void setIv(byte[] bytes) {
        this.iv = ModifiableVariableFactory.safelySetValue(iv, bytes);
    }
}
