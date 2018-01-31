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
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;

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
            @XmlElement(type = EllipticCurvesExtensionMessage.class, name = "SupportedGroups"),
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
            @XmlElement(type = HRRKeyShareExtensionMessage.class, name = "HRRKeyShareExtension"),
            @XmlElement(type = KeyShareExtensionMessage.class, name = "KeyShareExtension"),
            @XmlElement(type = SupportedVersionsExtensionMessage.class, name = "SupportedVersions"),
            @XmlElement(type = AlpnExtensionMessage.class, name = "ALPNExtension"),
            @XmlElement(type = CertificateStatusRequestExtensionMessage.class, name = "CertificateStatusRequestExtension"),
            @XmlElement(type = CertificateStatusRequestV2ExtensionMessage.class, name = "CertificateStatusRequestV2Extension"),
            @XmlElement(type = CertificateTypeExtensionMessage.class, name = "CertificateTypeExtension"),
            @XmlElement(type = ClientCertificateUrlExtensionMessage.class, name = "ClientCertificateUrlExtension"),
            @XmlElement(type = ClientCertificateTypeExtensionMessage.class, name = "ClientCertificateTypeExtension"),
            @XmlElement(type = ClientAuthzExtensionMessage.class, name = "ClientAuthorizationExtension"),
            @XmlElement(type = EncryptThenMacExtensionMessage.class, name = "EncryptThenMacExtension"),
            @XmlElement(type = ServerAuthzExtensionMessage.class, name = "ServerAuthorizationExtension"),
            @XmlElement(type = ServerCertificateTypeExtensionMessage.class, name = "ServerCertificateTypeExtension"),
            @XmlElement(type = SRPExtensionMessage.class, name = "SRPExtension"),
            @XmlElement(type = SrtpExtensionMessage.class, name = "SRTPExtension"),
            @XmlElement(type = TrustedCaIndicationExtensionMessage.class, name = "TrustedCaIndicationExtension"),
            @XmlElement(type = TruncatedHmacExtensionMessage.class, name = "TruncatedHmacExtension"),
            @XmlElement(type = EarlyDataExtensionMessage.class, name = "EarlyDataExtension"),
            @XmlElement(type = PSKKeyExchangeModesExtensionMessage.class, name = "PSKKeyExchangeModesExtension"),
            @XmlElement(type = PreSharedKeyExtensionMessage.class, name = "PreSharedKeyExtension"),
            @XmlElement(type = UnknownExtensionMessage.class, name = "UnknownExtension") })
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

    public HandshakeMessage(Config tlsConfig, HandshakeMessageType handshakeMessageType) {
        super();
        this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
        this.handshakeMessageType = handshakeMessageType;
    }

    public final List<ExtensionMessage> getExtensions() {
        return extensions;
    }

    public final void setExtensions(List<ExtensionMessage> extensions) {
        this.extensions = extensions;
    }

    public final void addExtension(ExtensionMessage extension) {
        if (this.extensions == null) {
            extensions = new LinkedList<>();
        }
        if (extension != null) {
            this.extensions.add(extension);
        } else {
            LOGGER.error("Cannot add null Extension");
        }
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
        StringBuilder sb = new StringBuilder();
        sb.append("\nHandshakeMessage:");
        sb.append("\n  Type: ");
        if (type != null && type.getValue() != null) {
            sb.append(type.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Length: ");
        if (length != null && length.getValue() != null) {
            sb.append(length.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  message_seq: ");
        if (messageSeq != null && messageSeq.getValue() != null) {
            sb.append(messageSeq.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  fragment_offset: ");
        if (fragmentOffset != null && fragmentOffset.getValue() != null) {
            sb.append(fragmentOffset.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  fragment_length: ");
        if (fragmentLength != null && fragmentLength.getValue() != null) {
            sb.append(fragmentLength.getValue());
        } else {
            sb.append("null");
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
                if (em != null) {
                    holders.addAll(em.getAllModifiableVariableHolders());
                }
            }
        }
        return holders;
    }
}
