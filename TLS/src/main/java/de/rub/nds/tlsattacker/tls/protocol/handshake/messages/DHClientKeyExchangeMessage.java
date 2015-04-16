/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    /**
     * DH modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableVariable<BigInteger> p;
    /**
     * DH generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableVariable<BigInteger> g;
    /**
     * server's public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableVariable<BigInteger> y;
    /**
     * client's private key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PRIVATE_KEY)
    ModifiableVariable<BigInteger> x;
    /**
     * Length of the serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableVariable<Integer> serializedPublicKeyLength;
    /**
     * serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableVariable<byte[]> serializedPublicKey;

    public DHClientKeyExchangeMessage() {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public DHClientKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<BigInteger> getP() {
	return p;
    }

    public void setP(ModifiableVariable<BigInteger> p) {
	this.p = p;
    }

    public void setP(BigInteger p) {
	this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public ModifiableVariable<BigInteger> getG() {
	return g;
    }

    public void setG(ModifiableVariable<BigInteger> g) {
	this.g = g;
    }

    public void setG(BigInteger g) {
	this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableVariable<BigInteger> getY() {
	return y;
    }

    public void setY(ModifiableVariable<BigInteger> y) {
	this.y = y;
    }

    public void setY(BigInteger y) {
	this.y = ModifiableVariableFactory.safelySetValue(this.y, y);
    }

    public ModifiableVariable<BigInteger> getX() {
	return x;
    }

    public void setX(ModifiableVariable<BigInteger> x) {
	this.x = x;
    }

    public void setX(BigInteger x) {
	this.x = ModifiableVariableFactory.safelySetValue(this.x, x);
    }

    public ModifiableVariable<Integer> getSerializedPublicKeyLength() {
	return serializedPublicKeyLength;
    }

    public void setSerializedPublicKeyLength(ModifiableVariable<Integer> serializedPublicKeyLength) {
	this.serializedPublicKeyLength = serializedPublicKeyLength;
    }

    public void setSerializedPublicKeyLength(Integer publicKeyLength) {
	this.serializedPublicKeyLength = ModifiableVariableFactory.safelySetValue(this.serializedPublicKeyLength,
		publicKeyLength);
    }

    public ModifiableVariable<byte[]> getSerializedPublicKey() {
	return serializedPublicKey;
    }

    public void setSerializedPublicKey(ModifiableVariable<byte[]> serializedPublicKey) {
	this.serializedPublicKey = serializedPublicKey;
    }

    public void setSerializedPublicKey(byte[] serializedPublicKey) {
	this.serializedPublicKey = ModifiableVariableFactory.safelySetValue(this.serializedPublicKey,
		serializedPublicKey);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder(super.toString());
	sb.append("\n  Y (client's public key): ").append(y.getValue().toString(16));
	return sb.toString();
    }
}
