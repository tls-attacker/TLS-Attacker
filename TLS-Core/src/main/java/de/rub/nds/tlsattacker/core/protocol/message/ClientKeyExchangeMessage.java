/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.computations.KeyExchangeComputations;
import java.util.Objects;

public abstract class ClientKeyExchangeMessage<Self extends ClientKeyExchangeMessage<?>>
        extends HandshakeMessage<Self> {

    /** Length of the serialized public key */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger publicKeyLength;
    /** serialized public key */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray publicKey;

    public ClientKeyExchangeMessage() {
        super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
    }

    public abstract KeyExchangeComputations getComputations();

    public abstract void prepareComputations();

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(Integer publicKeyLength) {
        this.publicKeyLength =
                ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
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

    @Override
    public String toShortString() {
        return "CKE";
    }

    @Override
    public int hashCode() {
        int hash = 7;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ClientKeyExchangeMessage other = (ClientKeyExchangeMessage) obj;
        if (!Objects.equals(this.publicKeyLength, other.publicKeyLength)) {
            return false;
        }
        return Objects.equals(this.publicKey, other.publicKey);
    }
}
