/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
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
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.xml.bind.annotation.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class HandshakeMessage extends TlsMessage {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlTransient
    protected boolean isIncludeInDigestDefault = true;

    @XmlTransient
    protected boolean isRetranmissionDefault = false;

    @XmlTransient
    protected final HandshakeMessageType handshakeMessageType;

    /**
     * handshake type
     */
    private ModifiableByte type = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean includeInDigest = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableBoolean retransmission = null;

    /**
     * List of extensions
     */
    @XmlElementWrapper
    @XmlElementRef
    @HoldsModifiableVariable
    private List<ExtensionMessage> extensions;

    @ModifiableVariableProperty
    private ModifiableByteArray extensionBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionsLength;

    private ModifiableInteger messageSequence;

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

    public final <T extends ExtensionMessage> T getExtension(Class<T> extensionClass) {
        if (this.getExtensions() == null) {
            return null;
        }
        List<ExtensionMessage> extensionMessages = new ArrayList<>(this.getExtensions());
        Optional<ExtensionMessage> extension =
            extensionMessages.stream().filter(i -> i.getClass().equals(extensionClass)).findFirst();
        if (extension.isPresent()) {
            return extensionClass.cast(extension.get());
        }
        return null;
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

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
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
            return isIncludeInDigestDefault;
        }
        return includeInDigest.getValue();
    }

    public boolean isRetransmission() {
        if (retransmission == null) {
            return isRetranmissionDefault;
        }
        return retransmission.getValue();
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

    public HandshakeMessageType getHandshakeMessageType() {
        return handshakeMessageType;
    }

    public void setIncludeInDigest(ModifiableBoolean includeInDigest) {
        this.includeInDigest = includeInDigest;
    }

    public void setIncludeInDigest(boolean includeInDigest) {
        this.includeInDigest = ModifiableVariableFactory.safelySetValue(this.includeInDigest, includeInDigest);
    }

    public ModifiableBoolean getIncludeInDigestModifiableBoolean() {
        return this.includeInDigest;
    }

    public void setRetransmission(ModifiableBoolean retransmission) {
        this.retransmission = retransmission;
    }

    public void setRetransmission(boolean retransmission) {
        this.retransmission = ModifiableVariableFactory.safelySetValue(this.retransmission, retransmission);
    }

    public ModifiableBoolean isRetransmissionModifiableBoolean() {
        return this.retransmission;
    }

    public ModifiableInteger getMessageSequence() {
        return messageSequence;
    }

    public void setMessageSequence(ModifiableInteger messageSequence) {
        this.messageSequence = messageSequence;
    }

    public void setMessageSequence(int messageSequence) {
        this.messageSequence = ModifiableVariableFactory.safelySetValue(this.messageSequence, messageSequence);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HandshakeMessage:");
        sb.append("\n  Type: ");
        if (type != null && type.getValue() != null) {
            sb.append(type.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Length: ");
        if (length != null && length.getValue() != null) {
            sb.append("\n  Length: ").append(length.getValue());
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append(handshakeMessageType.getName());
        if (isRetransmission()) {
            sb.append(" (retransmission)");
        }
        return sb.toString();
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
