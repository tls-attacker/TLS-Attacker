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
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
// @XmlType(propOrder = {"compressionLength", "cipherSuiteLength"})
public class ClientHelloMessage extends HelloMessage {

    /**
     * List of supported compression methods
     */
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = CompressionMethod.class, name = "CompressionMethod") })
    private List<CompressionMethod> supportedCompressionMethods = new LinkedList<>();
    /**
     * List of supported ciphersuites
     */
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = CipherSuite.class, name = "CipherSuite") })
    private List<CipherSuite> supportedCipherSuites = new LinkedList<>();
    /**
     * compression length
     */
    ModifiableVariable<Integer> compressionLength;
    /**
     * cipher suite byte length
     */
    ModifiableVariable<Integer> cipherSuiteLength;
    /**
     * array of supported ciphersuites
     */
    ModifiableVariable<byte[]> cipherSuites;
    /**
     * array of supported compressions
     */
    ModifiableVariable<byte[]> compressions;

    public ClientHelloMessage() {
	super(HandshakeMessageType.CLIENT_HELLO);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public ClientHelloMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CLIENT_HELLO);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<Integer> getCompressionLength() {
	return compressionLength;
    }

    public ModifiableVariable<Integer> getCipherSuiteLength() {
	return cipherSuiteLength;
    }

    public ModifiableVariable<byte[]> getCipherSuites() {
	return cipherSuites;
    }

    public ModifiableVariable<byte[]> getCompressions() {
	return compressions;
    }

    public void setCompressionLength(ModifiableVariable<Integer> compressionLength) {
	this.compressionLength = compressionLength;
    }

    public void setCipherSuiteLength(ModifiableVariable<Integer> cipherSuiteLength) {
	this.cipherSuiteLength = cipherSuiteLength;
    }

    public void setCipherSuites(ModifiableVariable<byte[]> cipherSuites) {
	this.cipherSuites = cipherSuites;
    }

    public void setCompressions(ModifiableVariable<byte[]> compressions) {
	this.compressions = compressions;
    }

    public void setCompressionLength(int compressionLength) {
	if (this.compressionLength == null) {
	    this.compressionLength = new ModifiableVariable<>();
	}
	this.compressionLength.setOriginalValue(compressionLength);
    }

    public void setCipherSuiteLength(int cipherSuiteLength) {
	if (this.cipherSuiteLength == null) {
	    this.cipherSuiteLength = new ModifiableVariable<>();
	}
	this.cipherSuiteLength.setOriginalValue(cipherSuiteLength);
    }

    public void setCipherSuites(byte[] array) {
	if (this.cipherSuites == null) {
	    this.cipherSuites = new ModifiableVariable<>();
	}
	this.cipherSuites.setOriginalValue(array);
    }

    public void setCompressions(byte[] array) {
	if (this.compressions == null) {
	    this.compressions = new ModifiableVariable<>();
	}
	this.compressions.setOriginalValue(array);
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
	this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public void setSupportedCipherSuites(List<CipherSuite> supportedCipherSuites) {
	this.supportedCipherSuites = supportedCipherSuites;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
	return supportedCompressionMethods;
    }

    // public void addExtension(ExtensionConfig extension) {
    // this.extensions.add(extension);
    // }
    //
    // public ExtensionConfig getExtension(ExtensionType extensionType) {
    // for(ExtensionConfig c : extensions) {
    // if(c.getExtensionType() == extensionType) {
    // return c;
    // }
    // }
    // return null;
    // }
    public List<CipherSuite> getSupportedCipherSuites() {
	return supportedCipherSuites;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append(super.toString()).append("\n  Protocol Version: ")
		.append(ProtocolVersion.getProtocolVersion(protocolVersion.getValue()))
		.append("\n  Client Unix Time: ")
		.append(new Date(ArrayConverter.bytesToLong(unixTime.getValue()) * 1000)).append("\n  Client Random: ")
		.append(ArrayConverter.bytesToHexString(random.getValue())).append("\n  Session ID: ")
		.append(ArrayConverter.bytesToHexString(sessionId.getValue())).append("\n  Supported Cipher Suites: ")
		.append(ArrayConverter.bytesToHexString(cipherSuites.getValue()))
		.append("\n  Supported Compression Methods: ")
		.append(ArrayConverter.bytesToHexString(compressions.getValue())).append("\n  Extensions: ");
	for (ExtensionMessage e : extensions) {
	    sb.append(e.toString());
	}
	return sb.toString();
    }
}
