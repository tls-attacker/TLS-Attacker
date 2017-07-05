/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.config.Config;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class HelloMessage extends HandshakeMessage {

    /**
     * protocol version in the client and server hello
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;
    /**
     * unix time
     */
    @ModifiableVariableProperty
    private ModifiableByteArray unixTime;
    /**
     * random
     */
    @ModifiableVariableProperty
    private ModifiableByteArray random;
    /**
     * length of the session id length field indicating the session id length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger sessionIdLength;
    /**
     * session id
     */
    @ModifiableVariableProperty
    private ModifiableByteArray sessionId;
    /**
     * List of extensions
     */
    @XmlElementWrapper
    @XmlElements(value = {
            @XmlElement(type = ECPointFormatExtensionMessage.class, name = "ECPointFormat"),
            @XmlElement(type = EllipticCurvesExtensionMessage.class, name = "EllipticCurves"),
            @XmlElement(type = ExtendedMasterSecretExtensionMessage.class, name = "ExtendedMasterSecretExtension"),
            @XmlElement(type = HeartbeatExtensionMessage.class, name = "HeartbeatExtension"),
            @XmlElement(type = MaxFragmentLengthExtensionMessage.class, name = "MaxFragmentLengthExtension"),
            @XmlElement(type = PaddingExtensionMessage.class, name = "PaddingExtension"),
            @XmlElement(type = RenegotiationInfoExtensionMessage.class, name = "RenegotiationInfoExtension"),
            @XmlElement(type = ServerNameIndicationExtensionMessage.class, name = "ServerNameIndicationExtension"),
            @XmlElement(type = SessionTicketTLSExtensionMessage.class, name = "SessionTicketTLSExtension"),
            @XmlElement(type = SignatureAndHashAlgorithmsExtensionMessage.class, name = "SignatureAndHashAlgorithmsExtension"),
            @XmlElement(type = SignedCertificateTimestampExtensionMessage.class, name = "SignedCertificateTimestampExtension"),
            @XmlElement(type = TokenBindingExtensionMessage.class, name = "TokenBindingExtension"),
            @XmlElement(type = UnknownExtensionMessage.class, name = "UnknownExtension") })
    @HoldsModifiableVariable
    private List<ExtensionMessage> extensions;

    @ModifiableVariableProperty
    private ModifiableByteArray extensionBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionsLength;

    public HelloMessage(HandshakeMessageType handshakeMessageType) {
        super(handshakeMessageType);
    }

    public HelloMessage(Config tlsConfig, HandshakeMessageType handshakeMessageType) {
        super(tlsConfig, handshakeMessageType);

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

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setUnixTime(ModifiableByteArray unixTime) {
        this.unixTime = unixTime;
    }

    public void setRandom(ModifiableByteArray random) {
        this.random = random;
    }

    public ModifiableInteger getExtensionsLength() {
        return extensionsLength;
    }

    public void setExtensionsLength(ModifiableInteger extensionsLength) {
        this.extensionsLength = extensionsLength;
    }

    public void setExtensionsLength(int extensionsLength) {
        this.extensionsLength = ModifiableVariableFactory.safelySetValue(this.extensionsLength, extensionsLength);
    }

    public ModifiableInteger getSessionIdLength() {
        return sessionIdLength;
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

    public void setExtensionBytes(byte[] extensionBytes) {
        this.extensionBytes = ModifiableVariableFactory.safelySetValue(this.extensionBytes, extensionBytes);
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
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

    public List<ExtensionMessage> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<ExtensionMessage> extensions) {
        this.extensions = extensions;
    }

    public void addExtension(ExtensionMessage extension) {
        if (this.extensions == null) {
            extensions = new LinkedList<>();
        }
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
                holders.addAll(em.getAllModifiableVariableHolders());
            }
        }
        return holders;
    }
}
