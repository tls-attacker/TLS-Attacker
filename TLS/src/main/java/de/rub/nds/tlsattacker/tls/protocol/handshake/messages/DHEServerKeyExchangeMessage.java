/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    /** DH modulus length */
    ModifiableVariable<Integer> pLength;
    /** DH modulus */
    ModifiableVariable<BigInteger> p;
    /** DH generator length */
    ModifiableVariable<Integer> gLength;
    /** DH generator */
    ModifiableVariable<BigInteger> g;
    /** public key length */
    ModifiableVariable<Integer> publicKeyLength;
    /** public key */
    ModifiableVariable<BigInteger> publicKey;

    public DHEServerKeyExchangeMessage() {
	super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public DHEServerKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<Integer> getpLength() {
	return pLength;
    }

    public void setpLength(ModifiableVariable<Integer> pLength) {
	this.pLength = pLength;
    }

    public void setpLength(Integer pLength) {
	this.pLength = ModifiableVariableFactory.safelySetValue(this.pLength, pLength);
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

    public ModifiableVariable<Integer> getgLength() {
	return gLength;
    }

    public void setgLength(ModifiableVariable<Integer> gLength) {
	this.gLength = gLength;
    }

    public void setgLength(Integer gLength) {
	this.gLength = ModifiableVariableFactory.safelySetValue(this.gLength, gLength);
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

    public ModifiableVariable<BigInteger> getPublicKey() {
	return publicKey;
    }

    public void setPublicKey(ModifiableVariable<BigInteger> publicKey) {
	this.publicKey = publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
	this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
    }

    public ModifiableVariable<Integer> getPublicKeyLength() {
	return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableVariable<Integer> publicKeyLength) {
	this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int length) {
	this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, length);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append(super.toString()).append("\n  Modulus p: ").append(p.getValue().toString(16))
		.append("\n  Generator g: ").append(g.getValue().toString(16)).append("\n  Public Key: ")
		.append(publicKey.getValue().toString(16)).append("\n  Signature Algorithm: ")
		.append(HashAlgorithm.getHashAlgorithm(this.hashAlgorithm.getValue())).append(" ")
		.append(SignatureAlgorithm.getSignatureAlgorithm(this.signatureAlgorithm.getValue()))
		.append("\n  Signature: ").append(ArrayConverter.bytesToHexString(this.signature.getValue()));

	return sb.toString();
    }
}
