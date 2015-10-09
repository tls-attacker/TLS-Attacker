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
package de.rub.nds.tlsattacker.tls.protocol.handshake.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Date;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerHelloMessage extends HelloMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray selectedCipherSuite;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte selectedCompressionMethod;

    public ServerHelloMessage() {
	super(HandshakeMessageType.SERVER_HELLO);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public ServerHelloMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.SERVER_HELLO);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByteArray getSelectedCipherSuite() {
	return selectedCipherSuite;
    }

    public void setSelectedCipherSuite(ModifiableByteArray selectedCipherSuite) {
	this.selectedCipherSuite = selectedCipherSuite;
    }

    public void setSelectedCipherSuite(byte[] value) {
	this.selectedCipherSuite = ModifiableVariableFactory.safelySetValue(this.selectedCipherSuite, value);
    }

    public ModifiableByte getSelectedCompressionMethod() {
	return selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(ModifiableByte selectedCompressionMethod) {
	this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(byte value) {
	this.selectedCompressionMethod = ModifiableVariableFactory
		.safelySetValue(this.selectedCompressionMethod, value);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append(super.toString()).append("\n  Protocol Version: ")
		.append(ProtocolVersion.getProtocolVersion(protocolVersion.getValue()))
		.append("\n  Server Unix Time: ")
		.append(new Date(ArrayConverter.bytesToLong(this.unixTime.getValue()) * 1000))
		.append("\n  Server Random: ").append(ArrayConverter.bytesToHexString(random.getValue()))
		.append("\n  Session ID: ").append(ArrayConverter.bytesToHexString(sessionId.getValue()))
		.append("\n  Selected Cipher Suite: ")
		.append(CipherSuite.getCipherSuite(selectedCipherSuite.getValue()))
		.append("\n  Selected Compression Method: ")
		.append(CompressionMethod.getCompressionMethod(selectedCompressionMethod.getValue()))
		.append("\n  Extensions: ");
	for (ExtensionMessage e : extensions) {
	    sb.append(e.toString());
	}
	return sb.toString();
    }
}
