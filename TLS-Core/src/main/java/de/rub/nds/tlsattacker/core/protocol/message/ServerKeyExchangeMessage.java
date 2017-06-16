/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.computations.KeyExchangeComputations;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class ServerKeyExchangeMessage extends HandshakeMessage {

    /**
     * hash algorithm
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte hashAlgorithm;
    /**
     * signature algorithm
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte signatureAlgorithm;
    /**
     * signature length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureLength;
    /**
     * signature
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.SIGNATURE)
    private ModifiableByteArray signature;

    /**
     * Length of the serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger publicKeyLength;
    /**
     * serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray publicKey;

    public ServerKeyExchangeMessage() {
        super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    public ServerKeyExchangeMessage(TlsConfig tlsConfig, HandshakeMessageType handshakeMessageType) {
        super(tlsConfig, handshakeMessageType);
    }

    public abstract KeyExchangeComputations getComputations();

    public abstract void prepareComputations();

    public ModifiableVariable<Byte> getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(ModifiableByte hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public void setHashAlgorithm(byte algorithm) {
        this.hashAlgorithm = ModifiableVariableFactory.safelySetValue(this.hashAlgorithm, algorithm);
    }

    public ModifiableVariable<Byte> getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(ModifiableByte signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public void setSignatureAlgorithm(byte algorithm) {
        this.signatureAlgorithm = ModifiableVariableFactory.safelySetValue(this.signatureAlgorithm, algorithm);
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int length) {
        this.signatureLength = ModifiableVariableFactory.safelySetValue(this.signatureLength, length);
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
        this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
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
}
