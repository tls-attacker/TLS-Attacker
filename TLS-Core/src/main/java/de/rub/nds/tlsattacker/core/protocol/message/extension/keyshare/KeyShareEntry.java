/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.math.BigInteger;

public class KeyShareEntry extends ModifiableVariableHolder {

    // TODO Should probably be in a computation class
    private NamedGroup groupConfig;
    private BigInteger privateKey;

    private ModifiableByteArray group;

    private ModifiableInteger publicKeyLength;

    private ModifiableByteArray publicKey;

    public KeyShareEntry() {
    }

    public KeyShareEntry(NamedGroup groupConfig, BigInteger privateKey) {
        this.groupConfig = groupConfig;
        this.privateKey = privateKey;
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

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int publicKeyLength) {
        this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }
}
