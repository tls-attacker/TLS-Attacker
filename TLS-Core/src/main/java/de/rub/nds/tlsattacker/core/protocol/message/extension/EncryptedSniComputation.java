/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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

    public void setClientHelloRandom(byte[] clientHelloRandom) {
        this.clientHelloRandom = ModifiableVariableFactory.safelySetValue(this.clientHelloRandom, clientHelloRandom);
    }

    public ModifiableByteArray getEsniContents() {
        return esniContents;
    }

    public void setEsniContents(ModifiableByteArray esniContents) {
        this.esniContents = esniContents;
    }

    public void setEsniContents(byte[] esniContents) {
        this.esniContents = ModifiableVariableFactory.safelySetValue(this.esniContents, esniContents);
    }

    public ModifiableByteArray getEsniRecordBytes() {
        return esniRecordBytes;
    }

    public void setEsniRecordBytes(ModifiableByteArray esniRecordBytes) {
        this.esniRecordBytes = esniRecordBytes;
    }

    public void setEsniRecordBytes(byte[] esniRecordBytes) {
        this.esniRecordBytes = ModifiableVariableFactory.safelySetValue(this.esniRecordBytes, esniRecordBytes);
    }

    public ModifiableByteArray getClientHelloKeyShare() {
        return clientHelloKeyShare;
    }

    public void setClientHelloKeyShare(ModifiableByteArray clientHelloKeyShare) {
        this.clientHelloKeyShare = clientHelloKeyShare;
    }

    public void setClientHelloKeyShare(byte[] clientHelloKeyShare) {
        this.clientHelloKeyShare =
            ModifiableVariableFactory.safelySetValue(this.clientHelloKeyShare, clientHelloKeyShare);
    }

    public ModifiableByteArray getEsniServerPublicKey() {
        return esniServerPublicKey;
    }

    public void setEsniServerPublicKey(ModifiableByteArray esniServerPublicKey) {
        this.esniServerPublicKey = esniServerPublicKey;
    }

    public void setEsniServerPublicKey(byte[] esniServerPublicKey) {
        this.esniServerPublicKey =
            ModifiableVariableFactory.safelySetValue(this.esniServerPublicKey, esniServerPublicKey);
    }

    public ModifiableByteArray getEsniContentsHash() {
        return esniContentsHash;
    }

    public void setEsniContentsHash(ModifiableByteArray esniContentsHash) {
        this.esniContentsHash = esniContentsHash;
    }

    public void setEsniContentsHash(byte[] esniContentsHash) {
        this.esniContentsHash = ModifiableVariableFactory.safelySetValue(this.esniContentsHash, esniContentsHash);
    }

    public ModifiableByteArray getEsniSharedSecret() {
        return esniSharedSecret;
    }

    public void setEsniSharedSecret(ModifiableByteArray esniSharedSecret) {
        this.esniSharedSecret = esniSharedSecret;
    }

    public void setEsniSharedSecret(byte[] esniSharedSecret) {
        this.esniSharedSecret = ModifiableVariableFactory.safelySetValue(this.esniSharedSecret, esniSharedSecret);
    }

    public ModifiableByteArray getEsniMasterSecret() {
        return esniMasterSecret;
    }

    public void setEsniMasterSecret(ModifiableByteArray esniMasterSecret) {
        this.esniMasterSecret = esniMasterSecret;
    }

    public void setEsniMasterSecret(byte[] esniMasterSecret) {
        this.esniMasterSecret = ModifiableVariableFactory.safelySetValue(this.esniMasterSecret, esniMasterSecret);
    }

    public ModifiableByteArray getEsniKey() {
        return esniKey;
    }

    public void setEsniKey(ModifiableByteArray esniKey) {
        this.esniKey = esniKey;
    }

    public void setEsniKey(byte[] esniKey) {
        this.esniKey = ModifiableVariableFactory.safelySetValue(this.esniKey, esniKey);
    }

    public ModifiableByteArray getEsniIv() {
        return esniIv;
    }

    public void setEsniIv(ModifiableByteArray esniIv) {
        this.esniIv = esniIv;
    }

    public void setEsniIv(byte[] esniIv) {
        this.esniIv = ModifiableVariableFactory.safelySetValue(this.esniIv, esniIv);
    }
}
