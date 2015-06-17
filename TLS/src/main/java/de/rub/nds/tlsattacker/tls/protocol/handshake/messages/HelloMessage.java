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

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
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
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray protocolVersion;
    /**
     * unix time
     */
    @ModifiableVariableProperty
    ModifiableByteArray unixTime;
    /**
     * random
     */
    @ModifiableVariableProperty
    ModifiableByteArray random;
    /**
     * length of the session id length field indicating the session id length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger sessionIdLength;
    /**
     * session id
     */
    @ModifiableVariableProperty
    ModifiableByteArray sessionId;
    /**
     * List of extensions
     */
    List<ExtensionMessage> extensions = new LinkedList<>();

    public HelloMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableByteArray getRandom() {
	return random;
    }

    public ModifiableByteArray getSessionId() {
	return sessionId;
    }

    public ModifiableByteArray getUnixTime() {
	return unixTime;
    }

    public ModifiableByteArray getProtocolVersion() {
	return protocolVersion;
    }

    public ModifiableInteger getSessionIdLength() {
	return sessionIdLength;
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public void setUnixTime(ModifiableByteArray unixTime) {
	this.unixTime = unixTime;
    }

    public void setRandom(ModifiableByteArray random) {
	this.random = random;
    }

    public void setSessionIdLength(ModifiableInteger sessionIdLength) {
	this.sessionIdLength = sessionIdLength;
    }

    public void setSessionId(ModifiableByteArray sessionId) {
	this.sessionId = sessionId;
    }

    public void setRandom(byte[] random) {
	this.random = ModifiableVariableFactory.safelySetValue(this.random, random);
    }

    public void setSessionId(byte[] sessionId) {
	this.sessionId = ModifiableVariableFactory.safelySetValue(this.sessionId, sessionId);
    }

    public void setUnixTime(byte[] unixTime) {
	this.unixTime = ModifiableVariableFactory.safelySetValue(this.unixTime, unixTime);
    }

    public void setSessionIdLength(int sessionIdLength) {
	this.sessionIdLength = ModifiableVariableFactory.safelySetValue(this.sessionIdLength, sessionIdLength);
    }

    public void setProtocolVersion(byte[] array) {
	this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
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
