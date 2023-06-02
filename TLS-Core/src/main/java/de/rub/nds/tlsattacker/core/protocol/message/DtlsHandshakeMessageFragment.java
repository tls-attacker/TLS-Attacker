/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.DtlsHandshakeMessageFragmentHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.DtlsHandshakeMessageFragmentParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DtlsHandshakeMessageFragmentPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Objects;

@XmlRootElement(name = "DtlsHandshakeMessageFragment")
public class DtlsHandshakeMessageFragment extends HandshakeMessage<DtlsHandshakeMessageFragment> {

    @ModifiableVariableProperty private ModifiableInteger fragmentOffset = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger fragmentLength = null;

    private ModifiableInteger epoch = null;

    private byte[] fragmentContentConfig = new byte[0];
    private int messageSequenceConfig;
    private int offsetConfig;
    private int handshakeMessageLengthConfig;
    private HandshakeMessageType handshakeMessageTypeConfig;
    private int maxFragmentLengthConfig;

    public DtlsHandshakeMessageFragment() {
        super(HandshakeMessageType.UNKNOWN);
        isIncludeInDigestDefault = false;
        adjustContextDefault = false;
    }

    public DtlsHandshakeMessageFragment(
            HandshakeMessageType handshakeMessageType,
            byte[] fragmentContentConfig,
            int messageSequenceConfig,
            int offsetConfig,
            int handshakeMessageLengthConfig) {
        super(handshakeMessageType);
        isIncludeInDigestDefault = false;
        adjustContextDefault = false;
        this.handshakeMessageTypeConfig = handshakeMessageType;
        this.fragmentContentConfig = fragmentContentConfig;
        this.messageSequenceConfig = messageSequenceConfig;
        this.offsetConfig = offsetConfig;
        this.handshakeMessageLengthConfig = handshakeMessageLengthConfig;
    }

    public DtlsHandshakeMessageFragment(Config tlsConfig) {
        super(HandshakeMessageType.UNKNOWN);
        isIncludeInDigestDefault = false;
        adjustContextDefault = false;
        this.maxFragmentLengthConfig = tlsConfig.getDtlsMaximumFragmentLength();
    }

    public DtlsHandshakeMessageFragment(Config tlsConfig, int maxFragmentLengthConfig) {
        super(HandshakeMessageType.UNKNOWN);
        isIncludeInDigestDefault = false;
        adjustContextDefault = false;
        this.maxFragmentLengthConfig = maxFragmentLengthConfig;
    }

    public DtlsHandshakeMessageFragment(HandshakeMessageType handshakeMessageType) {
        super(handshakeMessageType);
        isIncludeInDigestDefault = false;
        adjustContextDefault = false;
    }

    @Override
    public DtlsHandshakeMessageFragmentHandler getHandler(TlsContext tlsContext) {
        return new DtlsHandshakeMessageFragmentHandler(tlsContext);
    }

    @Override
    public DtlsHandshakeMessageFragmentParser getParser(TlsContext tlsContext, InputStream stream) {
        return new DtlsHandshakeMessageFragmentParser(stream, tlsContext);
    }

    @Override
    public DtlsHandshakeMessageFragmentPreparator getPreparator(TlsContext tlsContext) {
        return new DtlsHandshakeMessageFragmentPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public DtlsHandshakeMessageFragmentSerializer getSerializer(TlsContext tlsContext) {
        return new DtlsHandshakeMessageFragmentSerializer(this);
    }

    public HandshakeMessageType getHandshakeMessageTypeConfig() {
        return handshakeMessageTypeConfig;
    }

    public void setHandshakeMessageTypeConfig(HandshakeMessageType handshakeMessageTypeConfig) {
        this.handshakeMessageTypeConfig = handshakeMessageTypeConfig;
    }

    public Integer getMaxFragmentLengthConfig() {
        return maxFragmentLengthConfig;
    }

    public void setMaxFragmentLengthConfig(int maxFragmentLengthConfig) {
        this.maxFragmentLengthConfig = maxFragmentLengthConfig;
    }

    public byte[] getFragmentContentConfig() {
        return fragmentContentConfig;
    }

    public void setFragmentContentConfig(byte[] fragmentContentConfig) {
        this.fragmentContentConfig = fragmentContentConfig;
    }

    public int getMessageSequenceConfig() {
        return messageSequenceConfig;
    }

    public void setMessageSequenceConfig(int messageSequenceConfig) {
        this.messageSequenceConfig = messageSequenceConfig;
    }

    public int getOffsetConfig() {
        return offsetConfig;
    }

    public void setOffsetConfig(int offsetConfig) {
        this.offsetConfig = offsetConfig;
    }

    public int getHandshakeMessageLengthConfig() {
        return handshakeMessageLengthConfig;
    }

    public void setHandshakeMessageLengthConfig(int handshakeMessageLengthConfig) {
        this.handshakeMessageLengthConfig = handshakeMessageLengthConfig;
    }

    public ModifiableInteger getFragmentOffset() {
        return fragmentOffset;
    }

    public ModifiableInteger getFragmentLength() {
        return fragmentLength;
    }

    public void setFragmentOffset(int fragmentOffset) {
        this.fragmentOffset =
                ModifiableVariableFactory.safelySetValue(this.fragmentOffset, fragmentOffset);
    }

    public void setFragmentOffset(ModifiableInteger fragmentOffset) {
        this.fragmentOffset = fragmentOffset;
    }

    public void setFragmentLength(int fragmentLength) {
        this.fragmentLength =
                ModifiableVariableFactory.safelySetValue(this.fragmentLength, fragmentLength);
    }

    public void setFragmentLength(ModifiableInteger fragmentLength) {
        this.fragmentLength = fragmentLength;
    }

    public ModifiableInteger getEpoch() {
        return epoch;
    }

    public void setEpoch(ModifiableInteger epoch) {
        this.epoch = epoch;
    }

    public void setEpoch(int epoch) {
        this.epoch = ModifiableVariableFactory.safelySetValue(this.epoch, epoch);
    }

    @Override
    public String toCompactString() {
        return this.getHandshakeMessageType().name().toUpperCase() + "_DTLS_FRAGMENT";
    }

    @Override
    public String toShortString() {
        return "DTLS_FRAG";
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 67 * hash + Objects.hashCode(this.fragmentOffset);
        hash = 67 * hash + Objects.hashCode(this.fragmentLength);
        hash = 67 * hash + Objects.hashCode(this.epoch);
        hash = 67 * hash + Arrays.hashCode(this.fragmentContentConfig);
        hash = 67 * hash + this.messageSequenceConfig;
        hash = 67 * hash + this.offsetConfig;
        hash = 67 * hash + this.handshakeMessageLengthConfig;
        hash = 67 * hash + Objects.hashCode(this.handshakeMessageTypeConfig);
        hash = 67 * hash + this.maxFragmentLengthConfig;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DtlsHandshakeMessageFragment other = (DtlsHandshakeMessageFragment) obj;
        if (this.messageSequenceConfig != other.messageSequenceConfig) {
            return false;
        }
        if (this.offsetConfig != other.offsetConfig) {
            return false;
        }
        if (this.handshakeMessageLengthConfig != other.handshakeMessageLengthConfig) {
            return false;
        }
        if (this.maxFragmentLengthConfig != other.maxFragmentLengthConfig) {
            return false;
        }
        if (!Objects.equals(this.fragmentOffset, other.fragmentOffset)) {
            return false;
        }
        if (!Objects.equals(this.fragmentLength, other.fragmentLength)) {
            return false;
        }
        if (!Objects.equals(this.epoch, other.epoch)) {
            return false;
        }
        if (!Arrays.equals(this.fragmentContentConfig, other.fragmentContentConfig)) {
            return false;
        }
        return this.handshakeMessageTypeConfig == other.handshakeMessageTypeConfig;
    }
}
