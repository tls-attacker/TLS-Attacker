/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.frame;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.StreamFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.StreamFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.StreamFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.StreamFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** STREAM frames implicitly create a stream and carry stream data. */
@XmlRootElement(name = "StreamFrame")
public class StreamFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger streamId;

    @ModifiableVariableProperty protected ModifiableInteger offset;

    @ModifiableVariableProperty protected ModifiableInteger length;

    @ModifiableVariableProperty protected ModifiableByteArray data;

    private int streamIdConfig;
    private byte[] dataConfig;
    private int lengthConfig;
    private int offsetConfig;
    private boolean finalFrameConfig;

    public StreamFrame() {
        super(QuicFrameType.STREAM_FRAME);
    }

    public StreamFrame(QuicFrameType frameType) {
        super(frameType);
    }

    public StreamFrame(byte[] dataConfig, int streamIdConfig, boolean finalFrameConfig) {
        this();
        this.dataConfig = dataConfig;
        this.streamIdConfig = streamIdConfig;
        this.lengthConfig = dataConfig.length;
        this.finalFrameConfig = finalFrameConfig;
        this.offsetConfig = 0;
    }

    public StreamFrame(byte[] dataConfig, int streamIdConfig) {
        this(dataConfig, streamIdConfig, false);
    }

    @Override
    public StreamFrameHandler getHandler(Context context) {
        return new StreamFrameHandler(context.getQuicContext());
    }

    @Override
    public StreamFrameSerializer getSerializer(Context context) {
        return new StreamFrameSerializer(this);
    }

    @Override
    public StreamFramePreparator getPreparator(Context context) {
        return new StreamFramePreparator(context.getChooser(), this);
    }

    @Override
    public StreamFrameParser getParser(Context context, InputStream stream) {
        return new StreamFrameParser(stream);
    }

    public ModifiableInteger getStreamId() {
        return streamId;
    }

    public void setStreamId(int streamId) {
        this.streamId = ModifiableVariableFactory.safelySetValue(this.streamId, streamId);
    }

    public ModifiableInteger getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = ModifiableVariableFactory.safelySetValue(this.offset, offset);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    public int getStreamIdConfig() {
        return streamIdConfig;
    }

    public void setStreamIdConfig(int streamIdConfig) {
        this.streamIdConfig = streamIdConfig;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public int getLengthConfig() {
        return lengthConfig;
    }

    public void setLengthConfig(int lengthConfig) {
        this.lengthConfig = lengthConfig;
    }

    public int getOffsetConfig() {
        return offsetConfig;
    }

    public void setOffsetConfig(int offsetConfig) {
        this.offsetConfig = offsetConfig;
    }

    public boolean isFinalFrameConfig() {
        return finalFrameConfig;
    }

    public void setFinalFrameConfig(boolean finalFrameConfig) {
        this.finalFrameConfig = finalFrameConfig;
    }
}
