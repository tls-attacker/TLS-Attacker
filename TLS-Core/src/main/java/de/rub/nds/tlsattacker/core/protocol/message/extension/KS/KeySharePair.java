/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.KS;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;


public class KeySharePair extends ModifiableVariableHolder implements Serializable {

    private byte[] keyShareTypeConfig;
    private byte[] KeyShareConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray keyShareType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger keyShareLength;

    @ModifiableVariableProperty
    private ModifiableByteArray keyShare;

    public KeySharePair() {
    }

    public ModifiableByteArray getKeyShareType() {
        return keyShareType;
    }

    public void setKeyShareType(ModifiableByteArray keyShareTypeType) {
        this.keyShareType = keyShareTypeType;
    }

    public void setKeyShareType(byte[] keyShareType) {
        this.keyShareType = ModifiableVariableFactory.safelySetValue(this.keyShareType, keyShareType);
    }

    public ModifiableInteger getKeyShareLength() {
        return keyShareLength;
    }

    public void setKeyShareLength(ModifiableInteger serverNameLength) {
        this.keyShareLength = serverNameLength;
    }

    public void setKeyShareLength(int keyShareLength) {
        this.keyShareLength = ModifiableVariableFactory.safelySetValue(this.keyShareLength, keyShareLength);
    }

    public ModifiableByteArray getKeyShare() {
        return keyShare;
    }

    public void setKeyShare(ModifiableByteArray keyShare) {
        this.keyShare = keyShare;
    }

    public void setKeyShare(byte[] keyShare) {
        this.keyShare = ModifiableVariableFactory.safelySetValue(this.keyShare, keyShare);
    }

    public byte[] getKeyShareTypeConfig() {
        return keyShareTypeConfig;
    }

    public void setKeyShareTypeConfig(byte[] keyShareTypeConfig) {
        this.keyShareTypeConfig = keyShareTypeConfig;
    }

    public byte[] getKeyShareConfig() {
        return KeyShareConfig;
    }

    public void setKeyShareConfig(byte[] KeyShareConfig) {
        this.KeyShareConfig = KeyShareConfig;
    }

}
