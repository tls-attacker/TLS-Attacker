/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class GOSTClientComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray ukm;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray encryptedKey;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray macKey;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray keyEncryptionKey;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray maskKey;

    private ModifiableByteArray proxyKeyBlobs;

    private ModifiableString encryptionParamSet;

    private ModifiableBigInteger clientPublicKeyX;

    private ModifiableBigInteger clientPublicKeyY;

    @Override
    public void setSecretsInConfig(Config config) {

    }

    public byte[] getUkm() {
        return ukm.getValue();
    }

    public void setUkm(byte[] ukm) {
        this.ukm = ModifiableVariableFactory.safelySetValue(this.ukm, ukm);
    }

    public void setEncryptionParamSet(ASN1ObjectIdentifier oid) {
        this.encryptionParamSet = ModifiableVariableFactory.safelySetValue(this.encryptionParamSet, oid.getId());
    }

    public ASN1ObjectIdentifier getEncryptionParamSet() {
        return new ASN1ObjectIdentifier(encryptionParamSet.getValue());
    }

    public byte[] getEncryptedKey() {
        return encryptedKey.getValue();
    }

    public void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey = ModifiableVariableFactory.safelySetValue(this.encryptedKey, encryptedKey);
    }

    public byte[] getMacKey() {
        return macKey.getValue();
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = ModifiableVariableFactory.safelySetValue(this.macKey, macKey);
    }

    public byte[] getKeyEncryptionKey() {
        return keyEncryptionKey.getValue();
    }

    public byte[] getMaskKey() {
        return maskKey == null ? null : maskKey.getValue();
    }

    public byte[] getProxyKeyBlobs() {
        return proxyKeyBlobs == null ? null : proxyKeyBlobs.getValue();
    }

    public void setKeyEncryptionKey(byte[] keyEncryptionKey) {
        this.keyEncryptionKey = ModifiableVariableFactory.safelySetValue(this.keyEncryptionKey, keyEncryptionKey);
    }

    public CustomECPoint getClientPublicKey() {
        if (clientPublicKeyX != null && clientPublicKeyY != null) {
            return new CustomECPoint(clientPublicKeyX.getValue(), clientPublicKeyY.getValue());
        } else {
            return null;
        }
    }

    public void setClientPublicKey(CustomECPoint point) {
        this.clientPublicKeyX = ModifiableVariableFactory.safelySetValue(this.clientPublicKeyX, point.getX());
        this.clientPublicKeyY = ModifiableVariableFactory.safelySetValue(this.clientPublicKeyY, point.getY());
    }

    public void setUkm(ModifiableByteArray ukm) {
        this.ukm = ukm;
    }

    public void setCekEnc(ModifiableByteArray cekEnc) {
        this.encryptedKey = cekEnc;
    }

    public void setCekMac(ModifiableByteArray cekMac) {
        this.macKey = cekMac;
    }

    public void setKek(ModifiableByteArray kek) {
        this.keyEncryptionKey = kek;
    }

    public void setMaskKey(ModifiableByteArray maskKey) {
        this.maskKey = maskKey;
    }

    public void setProxyKeyBlobs(ModifiableByteArray proxyKeyBlobs) {
        this.proxyKeyBlobs = proxyKeyBlobs;
    }

    public void setEncryptionAlgOid(ModifiableString encryptionAlgOid) {
        this.encryptionParamSet = encryptionAlgOid;
    }

    public void setClientPublicKeyX(ModifiableBigInteger clientPublicKeyX) {
        this.clientPublicKeyX = clientPublicKeyX;
    }

    public void setClientPublicKeyY(ModifiableBigInteger clientPublicKeyY) {
        this.clientPublicKeyY = clientPublicKeyY;
    }

}
