/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.crypto.ec.Point;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class GOSTClientComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty private ModifiableByteArray ukm;

    @ModifiableVariableProperty private ModifiableByteArray encryptedKey;

    @ModifiableVariableProperty private ModifiableByteArray macKey;

    @ModifiableVariableProperty private ModifiableByteArray keyEncryptionKey;

    @ModifiableVariableProperty private ModifiableByteArray maskKey;

    @ModifiableVariableProperty private ModifiableByteArray proxyKeyBlobs;

    @ModifiableVariableProperty private ModifiableString encryptionParamSet;

    @ModifiableVariableProperty private ModifiableBigInteger clientPublicKeyX;

    @ModifiableVariableProperty private ModifiableBigInteger clientPublicKeyY;

    public GOSTClientComputations() {}

    public void setClientPublicKey(Point point) {
        if (point != null && point.getFieldX() != null && point.getFieldY() != null) {
            this.clientPublicKeyX =
                    ModifiableVariableFactory.safelySetValue(
                            this.clientPublicKeyX, point.getFieldX().getData());
            this.clientPublicKeyY =
                    ModifiableVariableFactory.safelySetValue(
                            this.clientPublicKeyY, point.getFieldY().getData());
        }
    }

    public ModifiableBigInteger getClientPublicKeyX() {
        return clientPublicKeyX;
    }

    public void setClientPublicKeyX(ModifiableBigInteger clientPublicKeyX) {
        this.clientPublicKeyX = clientPublicKeyX;
    }

    public ModifiableBigInteger getClientPublicKeyY() {
        return clientPublicKeyY;
    }

    public void setClientPublicKeyY(ModifiableBigInteger clientPublicKeyY) {
        this.clientPublicKeyY = clientPublicKeyY;
    }

    public ModifiableByteArray getEncryptedKey() {
        return encryptedKey;
    }

    public void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey =
                ModifiableVariableFactory.safelySetValue(this.encryptedKey, encryptedKey);
    }

    public ModifiableString getEncryptionParamSet() {
        return encryptionParamSet;
    }

    public void setEncryptionParamSet(ASN1ObjectIdentifier oid) {
        this.encryptionParamSet =
                ModifiableVariableFactory.safelySetValue(this.encryptionParamSet, oid.getId());
    }

    public ModifiableByteArray getKeyEncryptionKey() {
        return keyEncryptionKey;
    }

    public void setKeyEncryptionKey(byte[] keyEncryptionKey) {
        this.keyEncryptionKey =
                ModifiableVariableFactory.safelySetValue(this.keyEncryptionKey, keyEncryptionKey);
    }

    public ModifiableByteArray getMacKey() {
        return macKey;
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = ModifiableVariableFactory.safelySetValue(this.macKey, macKey);
    }

    public ModifiableByteArray getMaskKey() {
        return maskKey;
    }

    public void setMaskKey(ModifiableByteArray maskKey) {
        this.maskKey = maskKey;
    }

    public ModifiableByteArray getProxyKeyBlobs() {
        return proxyKeyBlobs;
    }

    public void setProxyKeyBlobs(ModifiableByteArray proxyKeyBlobs) {
        this.proxyKeyBlobs = proxyKeyBlobs;
    }

    public ModifiableByteArray getUkm() {
        return ukm;
    }

    public void setUkm(ModifiableByteArray ukm) {
        this.ukm = ukm;
    }

    public void setUkm(byte[] ukm) {
        this.ukm = ModifiableVariableFactory.safelySetValue(this.ukm, ukm);
    }

    public void setCekEnc(ModifiableByteArray cekEnc) {
        this.encryptedKey = cekEnc;
    }

    public void setCekMac(ModifiableByteArray cekMac) {
        this.macKey = cekMac;
    }

    public void setEncryptionAlgOid(ModifiableString encryptionAlgOid) {
        this.encryptionParamSet = encryptionAlgOid;
    }

    public void setKek(ModifiableByteArray kek) {
        this.keyEncryptionKey = kek;
    }
}
