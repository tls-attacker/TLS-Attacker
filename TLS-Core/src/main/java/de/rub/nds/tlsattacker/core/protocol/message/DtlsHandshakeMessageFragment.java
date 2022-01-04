/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.DtlsHandshakeMessageFragmentHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "DtlsHandshakeMessageFragment")
public class DtlsHandshakeMessageFragment extends HandshakeMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray content;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger messageSeq = null;

    @ModifiableVariableProperty
    private ModifiableInteger fragmentOffset = null;

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

    public DtlsHandshakeMessageFragment(HandshakeMessageType handshakeMessageType, byte[] fragmentContentConfig,
        int messageSequenceConfig, int offsetConfig, int handshakeMessageLengthConfig) {
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
        super(tlsConfig, HandshakeMessageType.UNKNOWN);
        isIncludeInDigestDefault = false;
        adjustContextDefault = false;
        this.maxFragmentLengthConfig = tlsConfig.getDtlsMaximumFragmentLength();
    }

    public DtlsHandshakeMessageFragment(Config tlsConfig, int maxFragmentLengthConfig) {
        super(tlsConfig, HandshakeMessageType.UNKNOWN);
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
    public DtlsHandshakeMessageFragmentHandler getHandler(TlsContext context) {
        return new DtlsHandshakeMessageFragmentHandler(context);
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

    public ModifiableByteArray getContent() {
        return content;
    }

    public void setContent(ModifiableByteArray content) {
        this.content = content;
    }

    public void setContent(byte[] content) {
        this.content = ModifiableVariableFactory.safelySetValue(this.content, content);
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

}
