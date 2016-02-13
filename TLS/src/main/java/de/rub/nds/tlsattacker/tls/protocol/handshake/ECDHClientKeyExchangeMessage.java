/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
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
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    /**
     * EC public key x coordinate
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableBigInteger publicKeyBaseX;
    /**
     * EC public key y coordinate
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableBigInteger publicKeyBaseY;
    /**
     * EC point format of the encoded EC point
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte ecPointFormat;
    /**
     * Encoded EC point (without EC point format)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableByteArray ecPointEncoded;
    /**
     * Supported EC point formats (can be used to trigger compression)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray supportedPointFormats;
    /**
     * Length of the serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger publicKeyLength;

    public ECDHClientKeyExchangeMessage() {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public ECDHClientKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableBigInteger getPublicKeyBaseX() {
	return publicKeyBaseX;
    }

    public void setPublicKeyBaseX(ModifiableBigInteger publicKeyBaseX) {
	this.publicKeyBaseX = publicKeyBaseX;
    }

    public void setPublicKeyBaseX(BigInteger ecPointBaseX) {
	this.publicKeyBaseX = ModifiableVariableFactory.safelySetValue(this.publicKeyBaseX, ecPointBaseX);
    }

    public ModifiableBigInteger getPublicKeyBaseY() {
	return publicKeyBaseY;
    }

    public void setPublicKeyBaseY(ModifiableBigInteger publicKeyBaseY) {
	this.publicKeyBaseY = publicKeyBaseY;
    }

    public void setPublicKeyBaseY(BigInteger ecPointBaseY) {
	this.publicKeyBaseY = ModifiableVariableFactory.safelySetValue(this.publicKeyBaseY, ecPointBaseY);
    }

    public ModifiableByte getEcPointFormat() {
	return ecPointFormat;
    }

    public void setEcPointFormat(ModifiableByte ecPointFormat) {
	this.ecPointFormat = ecPointFormat;
    }

    public void setEcPointFormat(Byte ecPointFormat) {
	this.ecPointFormat = ModifiableVariableFactory.safelySetValue(this.ecPointFormat, ecPointFormat);
    }

    public ModifiableByteArray getEcPointEncoded() {
	return ecPointEncoded;
    }

    public void setEcPointEncoded(ModifiableByteArray ecPointEncoded) {
	this.ecPointEncoded = ecPointEncoded;
    }

    public void setEcPointEncoded(byte[] ecPointEncoded) {
	this.ecPointEncoded = ModifiableVariableFactory.safelySetValue(this.ecPointEncoded, ecPointEncoded);
    }

    public ModifiableByteArray getSupportedPointFormats() {
	return supportedPointFormats;
    }

    public void setSupportedPointFormats(ModifiableByteArray supportedPointFormats) {
	this.supportedPointFormats = supportedPointFormats;
    }

    public void setSupportedPointFormats(byte[] supportedPointFormats) {
	this.supportedPointFormats = ModifiableVariableFactory.safelySetValue(this.supportedPointFormats,
		supportedPointFormats);
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

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder(super.toString());
	return sb.toString();
    }
}
