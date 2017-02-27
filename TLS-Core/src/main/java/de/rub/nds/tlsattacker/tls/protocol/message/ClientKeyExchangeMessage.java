/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class ClientKeyExchangeMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    protected ModifiableByteArray masterSecret;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    protected ModifiableByteArray premasterSecret;
    /**
     * Length of the serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger serializedPublicKeyLength;
    /**
     * serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray serializedPublicKey;

    public ClientKeyExchangeMessage() {
        super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
    }

    public ClientKeyExchangeMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
    }

    public ModifiableByteArray getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(ModifiableByteArray masterSecret) {
        this.masterSecret = masterSecret;
    }

    public void setMasterSecret(byte[] value) {
        this.masterSecret = ModifiableVariableFactory.safelySetValue(this.masterSecret, value);
    }

    public ModifiableByteArray getPremasterSecret() {
        return premasterSecret;
    }

    public void setPremasterSecret(ModifiableByteArray premasterSecret) {
        this.premasterSecret = premasterSecret;
    }

    public void setPremasterSecret(byte[] premasterSecret) {
        this.premasterSecret = ModifiableVariableFactory.safelySetValue(this.premasterSecret, premasterSecret);
    }

    public ModifiableInteger getSerializedPublicKeyLength() {
        return serializedPublicKeyLength;
    }

    public void setSerializedPublicKeyLength(ModifiableInteger serializedPublicKeyLength) {
        this.serializedPublicKeyLength = serializedPublicKeyLength;
    }

    public void setSerializedPublicKeyLength(Integer publicKeyLength) {
        this.serializedPublicKeyLength = ModifiableVariableFactory.safelySetValue(this.serializedPublicKeyLength,
                publicKeyLength);
    }

    public ModifiableByteArray getSerializedPublicKey() {
        return serializedPublicKey;
    }

    public void setSerializedPublicKey(ModifiableByteArray serializedPublicKey) {
        this.serializedPublicKey = serializedPublicKey;
    }

    public void setSerializedPublicKey(byte[] serializedPublicKey) {
        this.serializedPublicKey = ModifiableVariableFactory.safelySetValue(this.serializedPublicKey,
                serializedPublicKey);
    }

}
