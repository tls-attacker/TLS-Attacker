/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class HandshakeMessage extends ProtocolMessage {

    @XmlTransient
    protected boolean IS_INCLUDE_IN_DIGEST_DEFAULT = true;

    @XmlTransient
    protected final HandshakeMessageType handshakeMessageType;

    /**
     * handshake type
     */
    private ModifiableByte type = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger messageSeq = null;

    @ModifiableVariableProperty
    private ModifiableInteger fragmentOffset = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger fragmentLength = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean includeInDigest = null;

    /**
     * List of extensions
     */
    @XmlElementWrapper
    @XmlElements(value = {
            @XmlElement(type = ECPointFormatExtensionMessage.class, name = "ECPointFormat"),
            @XmlElement(type = EllipticCurvesExtensionMessage.class, name = "EllipticCurves"),
            @XmlElement(type = HeartbeatExtensionMessage.class, name = "HeartbeatExtension"),
            @XmlElement(type = MaxFragmentLengthExtensionMessage.class, name = "MaxFragmentLengthExtension"),
            @XmlElement(type = ServerNameIndicationExtensionMessage.class, name = "ServerNameIndicationExtension"),
            @XmlElement(type = SignatureAndHashAlgorithmsExtensionMessage.class, name = "SignatureAndHashAlgorithmsExtension") })
    @HoldsModifiableVariable
    private List<ExtensionMessage> extensions;

    @ModifiableVariableProperty
    private ModifiableByteArray extensionBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionsLength;
    
    public HandshakeMessage(HandshakeMessageType handshakeMessageType) {
        super();
        this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
        this.handshakeMessageType = handshakeMessageType;
    }

    public HandshakeMessage(TlsConfig tlsConfig, HandshakeMessageType handshakeMessageType) {
        super();
        this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
        this.handshakeMessageType = handshakeMessageType;
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
    
    public void setExtensionBytes(byte[] extensionBytes) {
        this.extensionBytes = ModifiableVariableFactory.safelySetValue(this.extensionBytes, extensionBytes);
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
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
    
    public ModifiableByte getType() {
        return type;
    }

    public boolean getIncludeInDigest() {
        if (includeInDigest == null) {
            return IS_INCLUDE_IN_DIGEST_DEFAULT;
        }
        return includeInDigest.getValue();
    }

    public void setType(ModifiableByte type) {
        this.type = type;
    }

    public void setType(Byte type) {
        this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public ModifiableInteger getMessageSeq() {
        return messageSeq;
    }

    public ModifiableInteger getFragmentOffset() {
        return fragmentOffset;
    }

    public ModifiableInteger getFragmentLength() {
        return fragmentLength;
    }

    public void setMessageSeq(int messageSeq) {
        this.messageSeq = ModifiableVariableFactory.safelySetValue(this.messageSeq, messageSeq);
    }

    public void setMessageSeq(ModifiableInteger messageSeq) {
        this.messageSeq = messageSeq;
    }

    public void setFragmentOffset(int fragmentOffset) {
        this.fragmentOffset = ModifiableVariableFactory.safelySetValue(this.fragmentOffset, fragmentOffset);
    }

    public void setFragmentOffset(ModifiableInteger fragmentOffset) {
        this.fragmentOffset = fragmentOffset;
    }

    public void setFragmentLength(int fragmentLength) {
        this.fragmentLength = ModifiableVariableFactory.safelySetValue(this.fragmentLength, fragmentLength);
    }

    public void setFragmentLength(ModifiableInteger fragmentLength) {
        this.fragmentLength = fragmentLength;
    }

    public HandshakeMessageType getHandshakeMessageType() {
        return handshakeMessageType;
    }

    public void setIncludeInDigest(boolean includeInDigest) {
        this.includeInDigest = ModifiableVariableFactory.safelySetValue(this.includeInDigest, includeInDigest);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Type: ").append(type.getValue());
        sb.append("\n  Length: ").append(length.getValue());
        if (messageSeq != null && messageSeq.getValue() != null) {
            sb.append("\n  message_seq: ").append(messageSeq.getValue());
        }
        if (fragmentOffset != null && fragmentOffset.getValue() != null) {
            sb.append("\n  fragment_offset: ").append(fragmentOffset.getValue());
        }
        if (fragmentLength != null && fragmentLength.getValue() != null) {
            sb.append("\n  fragment_length: ").append(fragmentLength.getValue());
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        return handshakeMessageType.getName();
    }
    
    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (getExtensions() != null) {
            for (ExtensionMessage em : getExtensions()) {
                holders.add(em);
            }
        }
        return holders;
    }
}
