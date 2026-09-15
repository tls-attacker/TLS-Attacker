/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.protocol.crypto.key.MlKemPrivateKey;
import de.rub.nds.protocol.crypto.key.MlKemPublicKey;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.math.BigInteger;

@XmlAccessorType(XmlAccessType.FIELD)
public class KeyShareEntry extends ModifiableVariableHolder {

    private NamedGroup groupConfig;
    private BigInteger dhPrivateKey;
    private MlKemPrivateKey mlKemPrivateKey;
    private MlKemPublicKey mlKemPublicKeyContainer;

    private ModifiableByteArray group;

    private ModifiableInteger publicKeyLength;

    private ModifiableByteArray publicKey;
    private ModifiableByteArray dhPublicKey;
    private ModifiableByteArray mlKemPublicKey;
    private ModifiableByteArray mlKemCiphertext;

    public KeyShareEntry() {}

    public KeyShareEntry(NamedGroup groupConfig, BigInteger dhPrivateKey) {
        this.groupConfig = groupConfig;
        this.dhPrivateKey = dhPrivateKey;
    }

    public NamedGroup getGroupConfig() {
        return groupConfig;
    }

    public void setGroupConfig(NamedGroup groupConfig) {
        this.groupConfig = groupConfig;
    }

    public ModifiableByteArray getGroup() {
        return group;
    }

    public void setGroup(ModifiableByteArray group) {
        this.group = group;
    }

    public void setGroup(byte[] group) {
        this.group = ModifiableVariableFactory.safelySetValue(this.group, group);
    }

    public ModifiableByteArray getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ModifiableByteArray publicKey) {
        this.publicKey = publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
    }

    public ModifiableByteArray getDhPublicKey() {
        return dhPublicKey;
    }

    public void setDhPublicKey(ModifiableByteArray dhPublicKey) {
        this.dhPublicKey = dhPublicKey;
    }

    public void setDhPublicKey(byte[] dhPublicKey) {
        this.dhPublicKey = ModifiableVariableFactory.safelySetValue(this.dhPublicKey, dhPublicKey);
    }

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int publicKeyLength) {
        this.publicKeyLength =
                ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
    }

    public BigInteger getDhPrivateKey() {
        return dhPrivateKey;
    }

    public void setDhPrivateKey(BigInteger dhPrivateKey) {
        this.dhPrivateKey = dhPrivateKey;
    }

    public byte[] getMlKemPrivateKey() {
        return mlKemPrivateKey.getDecapsulationKey();
    }

    public MlKemPrivateKey getMlKemPrivateKeyContainer() {
        return mlKemPrivateKey;
    }

    public void setMlKemPrivateKey(MlKemPrivateKey mlKemPrivateKey) {
        this.mlKemPrivateKey = mlKemPrivateKey;
    }

    public ModifiableByteArray getMlKemPublicKey() {
        return mlKemPublicKey;
    }

    public void setMlKemPublicKey(MlKemPublicKey mlKemPublicKeyContainer) {
        this.mlKemPublicKeyContainer = mlKemPublicKeyContainer; // Store the object
        this.mlKemPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.mlKemPublicKey, mlKemPublicKeyContainer.getEncapsulationKey());
    }

    public void setMlKemPublicKey(ModifiableByteArray mlKemPublicKey) {
        this.mlKemPublicKey = mlKemPublicKey;
    }

    public MlKemPublicKey getMlKemPublicKeyContainer() {
        return mlKemPublicKeyContainer;
    }

    public ModifiableByteArray getMlKemCiphertext() {
        return mlKemCiphertext;
    }

    public void setMlKemCiphertext(ModifiableByteArray mlKemCiphertext) {
        this.mlKemCiphertext = mlKemCiphertext;
    }

    public void setMlKemCiphertext(byte[] mlKemCiphertext) {
        this.mlKemCiphertext =
                ModifiableVariableFactory.safelySetValue(this.mlKemCiphertext, mlKemCiphertext);
    }
}
