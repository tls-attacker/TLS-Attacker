/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class HandshakeMessage<Self extends HandshakeMessage<?>>
        extends ProtocolMessage<Self> {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlTransient protected boolean isIncludeInDigestDefault = true;

    @XmlTransient protected boolean isRetranmissionDefault = false;

    @XmlTransient protected final HandshakeMessageType handshakeMessageType;

    /** handshake type */
    private ModifiableByte type = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean includeInDigest = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableBoolean retransmission = null;

    private ModifiableByteArray messageContent = null;
    /** List of extensions */
    @XmlElementWrapper @XmlElementRef @HoldsModifiableVariable
    private List<ExtensionMessage> extensions;

    @ModifiableVariableProperty private ModifiableByteArray extensionBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger messageSequence = null;

    public HandshakeMessage(HandshakeMessageType handshakeMessageType) {
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
                extensionMessages.stream()
                        .filter(i -> i.getClass().equals(extensionClass))
                        .findFirst();
        if (extension.isPresent()) {
            return extensionClass.cast(extension.get());
        }
        return null;
    }

    public final void setExtensions(List<ExtensionMessage> extensions) {
        this.extensions = extensions;
    }

    public List<ExtensionMessage> createConfiguredExtensions(Config tlsConfig) {
        return new LinkedList<>();
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
        if (extensions != null) {
            for (ExtensionMessage e : extensions) {
                if (e.getExtensionTypeConstant() == extensionType) {
                    return true;
                }
            }
        }
        return false;
    }

    public void setExtensionBytes(byte[] extensionBytes) {
        this.extensionBytes =
                ModifiableVariableFactory.safelySetValue(this.extensionBytes, extensionBytes);
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
        this.extensionsLength =
                ModifiableVariableFactory.safelySetValue(this.extensionsLength, extensionsLength);
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
        this.includeInDigest =
                ModifiableVariableFactory.safelySetValue(this.includeInDigest, includeInDigest);
    }

    public ModifiableBoolean getIncludeInDigestModifiableBoolean() {
        return this.includeInDigest;
    }

    public void setRetransmission(ModifiableBoolean retransmission) {
        this.retransmission = retransmission;
    }

    public void setRetransmission(boolean retransmission) {
        this.retransmission =
                ModifiableVariableFactory.safelySetValue(this.retransmission, retransmission);
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
        this.messageSequence =
                ModifiableVariableFactory.safelySetValue(this.messageSequence, messageSequence);
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
            sb.append(" (ret.)");
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

    @Override
    public abstract HandshakeMessageParser<Self> getParser(
            TlsContext tlsContext, InputStream stream);

    @Override
    public abstract HandshakeMessagePreparator<Self> getPreparator(TlsContext tlsContext);

    @Override
    public abstract HandshakeMessageSerializer<Self> getSerializer(TlsContext tlsContext);

    @Override
    public abstract HandshakeMessageHandler<Self> getHandler(TlsContext tlsContext);

    public ModifiableByteArray getMessageContent() {
        return messageContent;
    }

    public void setMessageContent(ModifiableByteArray messageContent) {
        this.messageContent = messageContent;
    }

    public void setMessageContent(byte[] content) {
        this.messageContent =
                ModifiableVariableFactory.safelySetValue(this.messageContent, content);
    }
}
