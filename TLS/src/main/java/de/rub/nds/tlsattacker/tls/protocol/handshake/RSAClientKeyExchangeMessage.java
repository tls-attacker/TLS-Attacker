/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RSAClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger encryptedPremasterSecretLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    ModifiableByteArray encryptedPremasterSecret;

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    ModifiableByteArray plainPaddedPremasterSecret;

    public RSAClientKeyExchangeMessage() {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public RSAClientKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableInteger getEncryptedPremasterSecretLength() {
	return encryptedPremasterSecretLength;
    }

    public void setEncryptedPremasterSecretLength(ModifiableInteger encryptedPremasterSecretLength) {
	this.encryptedPremasterSecretLength = encryptedPremasterSecretLength;
    }

    public void setEncryptedPremasterSecretLength(int length) {
	this.encryptedPremasterSecretLength = ModifiableVariableFactory.safelySetValue(
		this.encryptedPremasterSecretLength, length);
    }

    public ModifiableByteArray getEncryptedPremasterSecret() {
	return encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(ModifiableByteArray encryptedPremasterSecret) {
	this.encryptedPremasterSecret = encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(byte[] value) {
	this.encryptedPremasterSecret = ModifiableVariableFactory.safelySetValue(this.encryptedPremasterSecret, value);
    }

    public ModifiableByteArray getPlainPaddedPremasterSecret() {
	return plainPaddedPremasterSecret;
    }

    public void setPlainPaddedPremasterSecret(ModifiableByteArray plainPaddedPremasterSecret) {
	this.plainPaddedPremasterSecret = plainPaddedPremasterSecret;
    }

    public void setPlainPaddedPremasterSecret(byte[] value) {
	this.plainPaddedPremasterSecret = ModifiableVariableFactory.safelySetValue(this.plainPaddedPremasterSecret,
		value);
    }

    public void setMasterSecret(ModifiableByteArray masterSecret) {
	this.masterSecret = masterSecret;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nClient Key Exchange message:");
	return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext)
    {
        ProtocolMessageHandler handler = new RSAClientKeyExchangeHandler(tlsContext);
        handler.setProtocolMessage(this);
        return handler;
    }
}
