/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.computations.KeyExchangeComputations;
import java.util.Objects;

public abstract class ServerKeyExchangeMessage extends HandshakeMessage {

    /** signature and hash algorithm */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray signatureAndHashAlgorithm;
    /** signature length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureLength;
    /** signature */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.SIGNATURE)
    private ModifiableByteArray signature;

    /** Length of the serialized public key */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger publicKeyLength;
    /** serialized public key */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray publicKey;

    @HoldsModifiableVariable private SignatureComputations signatureComputations;

    public ServerKeyExchangeMessage() {
        super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    public abstract KeyExchangeComputations getKeyExchangeComputations();

    public abstract void prepareKeyExchangeComputations();

    public SignatureComputations getSignatureComputations(SignatureAlgorithm algorithm) {
        // TODO its unlucky that this design can cause a conflict here if the type mismatches
        if (signatureComputations == null) {
            SignatureCalculator calculator = new SignatureCalculator();
            signatureComputations = calculator.createSignatureComputations(algorithm);
        }
        return signatureComputations;
    }

    public ModifiableByteArray getSignatureAndHashAlgorithm() {
        return signatureAndHashAlgorithm;
    }

    public void setSignatureAndHashAlgorithm(ModifiableByteArray signatureAndHashAlgorithm) {
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    public void setSignatureAndHashAlgorithm(byte[] signatureAndHashAlgorithm) {
        this.signatureAndHashAlgorithm =
                ModifiableVariableFactory.safelySetValue(
                        this.signatureAndHashAlgorithm, signatureAndHashAlgorithm);
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int length) {
        this.signatureLength =
                ModifiableVariableFactory.safelySetValue(this.signatureLength, length);
    }

    public ModifiableByteArray getSignature() {
        return signature;
    }

    public void setSignature(ModifiableByteArray signature) {
        this.signature = signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

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
        return "SKE";
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + Objects.hashCode(this.signatureAndHashAlgorithm);
        hash = 83 * hash + Objects.hashCode(this.signatureLength);
        hash = 83 * hash + Objects.hashCode(this.signature);
        hash = 83 * hash + Objects.hashCode(this.publicKeyLength);
        hash = 83 * hash + Objects.hashCode(this.publicKey);
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
        final ServerKeyExchangeMessage other = (ServerKeyExchangeMessage) obj;
        if (!Objects.equals(this.signatureAndHashAlgorithm, other.signatureAndHashAlgorithm)) {
            return false;
        }
        if (!Objects.equals(this.signatureLength, other.signatureLength)) {
            return false;
        }
        if (!Objects.equals(this.signature, other.signature)) {
            return false;
        }
        if (!Objects.equals(this.publicKeyLength, other.publicKeyLength)) {
            return false;
        }
        return Objects.equals(this.publicKey, other.publicKey);
    }
}
