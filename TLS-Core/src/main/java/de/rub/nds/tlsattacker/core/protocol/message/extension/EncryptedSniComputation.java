/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;

public class EncryptedSniComputation extends ModifiableVariableHolder {

    @ModifiableVariableProperty
    private ModifiableByteArray clientHelloRandom;

    @ModifiableVariableProperty
    private ModifiableByteArray esniContents;

    @ModifiableVariableProperty
    private ModifiableByteArray esniRecordBytes;

    @ModifiableVariableProperty
    private ModifiableByteArray clientHelloKeyShare;

    @ModifiableVariableProperty
    private ModifiableByteArray esniServerPublicKey;

    @ModifiableVariableProperty
    private ModifiableByteArray esniContentsHash;

    @ModifiableVariableProperty
    private ModifiableByteArray esniSharedSecret;

    @ModifiableVariableProperty
    private ModifiableByteArray esniMasterSecret;

    @ModifiableVariableProperty
    private ModifiableByteArray esniKey;

    @ModifiableVariableProperty
    private ModifiableByteArray esniIv;

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

    public ModifiableByteArray getEsniRecordBytes() {
        return esniRecordBytes;
    }

    public void setEsniRecordBytes(ModifiableByteArray recordBytes) {
        this.esniRecordBytes = recordBytes;
    }

    public void setEsniRecordBytes(byte[] bytes) {
        this.esniRecordBytes = ModifiableVariableFactory.safelySetValue(esniRecordBytes, bytes);
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

    public ModifiableByteArray getEsniServerPublicKey() {
        return esniServerPublicKey;
    }

    public void setEsniServerPublicKey(ModifiableByteArray pk) {
        this.esniServerPublicKey = pk;
    }

    public void setEsniServerPublicKey(byte[] bytes) {
        this.esniServerPublicKey = ModifiableVariableFactory.safelySetValue(esniServerPublicKey, bytes);
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

    public ModifiableByteArray getEsniKey() {
        return esniKey;
    }

    public void setKey(ModifiableByteArray esniKey) {
        this.esniKey = esniKey;
    }

    public void setEsniKey(byte[] bytes) {
        this.esniKey = ModifiableVariableFactory.safelySetValue(esniKey, bytes);
    }

    public ModifiableByteArray getEsniIv() {
        return esniIv;
    }

    public void setEsniIv(ModifiableByteArray iv) {
        this.esniIv = iv;
    }

    public void setEsniIv(byte[] bytes) {
        this.esniIv = ModifiableVariableFactory.safelySetValue(esniIv, bytes);
    }
}
