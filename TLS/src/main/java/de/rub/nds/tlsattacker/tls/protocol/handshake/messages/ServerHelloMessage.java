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
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Date;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerHelloMessage extends HelloMessage {

    ModifiableVariable<byte[]> selectedCipherSuite;

    ModifiableVariable<Byte> selectedCompressionMethod;

    public ServerHelloMessage() {
	super(HandshakeMessageType.SERVER_HELLO);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public ServerHelloMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.SERVER_HELLO);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<byte[]> getSelectedCipherSuite() {
	return selectedCipherSuite;
    }

    public void setSelectedCipherSuite(ModifiableVariable<byte[]> selectedCipherSuite) {
	this.selectedCipherSuite = selectedCipherSuite;
    }

    public void setSelectedCipherSuite(byte[] value) {
	if (this.selectedCipherSuite == null) {
	    this.selectedCipherSuite = new ModifiableVariable<>();
	}
	this.selectedCipherSuite.setOriginalValue(value);
    }

    public ModifiableVariable<Byte> getSelectedCompressionMethod() {
	return selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(ModifiableVariable<Byte> selectedCompressionMethod) {
	this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(byte value) {
	if (this.selectedCompressionMethod == null) {
	    this.selectedCompressionMethod = new ModifiableVariable<>();
	}
	this.selectedCompressionMethod.setOriginalValue(value);
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
