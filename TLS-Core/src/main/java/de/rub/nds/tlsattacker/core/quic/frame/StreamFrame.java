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
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** STREAM frames implicitly create a stream and carry stream data. */
@XmlRootElement(name = "StreamFrame")
public class StreamFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger streamId;

    @ModifiableVariableProperty protected ModifiableInteger offset;

    @ModifiableVariableProperty protected ModifiableInteger length;

    @ModifiableVariableProperty protected ModifiableByteArray data;

    protected boolean isFinalFrame;

    public StreamFrame() {
        super(QuicFrameType.STREAM_FRAME);
    }

    public StreamFrame(byte[] data, int streamId, boolean isFinalFrame) {
        this();
        setData(data);
        setLength(data.length);
        setStreamId(streamId);
        setFinalFrame(isFinalFrame);
    }

    public StreamFrame(byte[] data, int streamId) {
        this(data, streamId, false);
    }

    public StreamFrame(QuicFrameType frameType) {
        super(frameType);
    }

    @Override
    public StreamFrameHandler getHandler(QuicContext context) {
        return new StreamFrameHandler(context);
    }

    @Override
    public StreamFrameSerializer getSerializer(QuicContext context) {
        return new StreamFrameSerializer(this);
    }

    @Override
    public StreamFramePreparator getPreparator(QuicContext context) {
        return new StreamFramePreparator(context.getChooser(), this);
    }

    @Override
    public StreamFrameParser getParser(QuicContext context, InputStream stream) {
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

    public boolean isFinalFrame() {
        return isFinalFrame;
    }

    public void setFinalFrame(boolean finalFrame) {
        this.isFinalFrame = finalFrame;
    }
}
