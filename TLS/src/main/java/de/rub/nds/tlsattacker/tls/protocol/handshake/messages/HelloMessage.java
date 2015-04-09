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
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
abstract class HelloMessage extends HandshakeMessage {

    /**
     * protocol version in the client and server hello
     */
    ModifiableVariable<byte[]> protocolVersion;
    /**
     * unix time
     */
    ModifiableVariable<byte[]> unixTime;
    /**
     * random
     */
    ModifiableVariable<byte[]> random;
    /**
     * length of the session id length field indicating the session id length
     */
    ModifiableVariable<Integer> sessionIdLength;
    /**
     * session id
     */
    ModifiableVariable<byte[]> sessionId;
    /**
     * List of extensions
     */
    List<ExtensionMessage> extensions = new LinkedList<>();

    public HelloMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableVariable<byte[]> getRandom() {
	return random;
    }

    public ModifiableVariable<byte[]> getSessionId() {
	return sessionId;
    }

    public ModifiableVariable<byte[]> getUnixTime() {
	return unixTime;
    }

    public ModifiableVariable<byte[]> getProtocolVersion() {
	return protocolVersion;
    }

    public ModifiableVariable<Integer> getSessionIdLength() {
	return sessionIdLength;
    }

    public void setProtocolVersion(ModifiableVariable<byte[]> protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public void setUnixTime(ModifiableVariable<byte[]> unixTime) {
	this.unixTime = unixTime;
    }

    public void setRandom(ModifiableVariable<byte[]> random) {
	this.random = random;
    }

    public void setSessionIdLength(ModifiableVariable<Integer> sessionIdLength) {
	this.sessionIdLength = sessionIdLength;
    }

    public void setSessionId(ModifiableVariable<byte[]> sessionId) {
	this.sessionId = sessionId;
    }

    public void setRandom(byte[] random) {
	if (this.random == null) {
	    this.random = new ModifiableVariable<>();
	}
	this.random.setOriginalValue(random);
    }

    public void setSessionId(byte[] sessionId) {
	if (this.sessionId == null) {
	    this.sessionId = new ModifiableVariable<>();
	}
	this.sessionId.setOriginalValue(sessionId);
    }

    public void setUnixTime(byte[] unixTime) {
	if (this.unixTime == null) {
	    this.unixTime = new ModifiableVariable<>();
	}
	this.unixTime.setOriginalValue(unixTime);
    }

    public void setSessionIdLength(int sessionIdLength) {
	if (this.sessionIdLength == null) {
	    this.sessionIdLength = new ModifiableVariable<>();
	}
	this.sessionIdLength.setOriginalValue(sessionIdLength);
    }

    public void setProtocolVersion(byte[] array) {
	if (this.protocolVersion == null) {
	    this.protocolVersion = new ModifiableVariable<>();
	}
	this.protocolVersion.setOriginalValue(array);
    }

    @XmlElementWrapper
    @XmlElements(value = {
	    @XmlElement(type = ECPointFormatExtensionMessage.class, name = "ECPointFormat"),
	    @XmlElement(type = EllipticCurvesExtensionMessage.class, name = "EllipticCurves"),
	    @XmlElement(type = HeartbeatExtensionMessage.class, name = "HeartbeatExtension"),
	    @XmlElement(type = MaxFragmentLengthExtensionMessage.class, name = "MaxFragmentLengthExtension"),
	    @XmlElement(type = ServerNameIndicationExtensionMessage.class, name = "ServerNameIndicationExtension"),
	    @XmlElement(type = SignatureAndHashAlgorithmsExtensionMessage.class, name = "SignatureAndHashAlgorithmsExtension") })
    public List<ExtensionMessage> getExtensions() {
	return extensions;
    }

    public void setExtensions(List<ExtensionMessage> extensions) {
	this.extensions = extensions;
    }

    public void addExtension(ExtensionMessage extension) {
	this.extensions.add(extension);
    }

    public boolean containsExtension(ExtensionType extensionType) {
	for (ExtensionMessage e : extensions) {
	    if (e.getExtensionTypeConstant() == extensionType) {
		return true;
	    }
	}
	return false;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
	List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
	if (extensions != null) {
	    for (ExtensionMessage em : extensions) {
		holders.add(em);
	    }
	}
	return holders;
    }
}
