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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.MaxStreamDataFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.MaxStreamDataFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.MaxStreamDataFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.MaxStreamDataFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class MaxStreamDataFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger streamId;

    @ModifiableVariableProperty protected ModifiableInteger maximumStreamData;

    private int streamIdConfig;

    private int maximumStreamDataConfig;

    public MaxStreamDataFrame() {
        super(QuicFrameType.MAX_STREAM_DATA_FRAME);
    }

    public MaxStreamDataFrame(int streamIdConfig, int maximumStreamDataConfig) {
        this();
        this.streamIdConfig = streamIdConfig;
        this.maximumStreamDataConfig = maximumStreamDataConfig;
    }

    @Override
    public MaxStreamDataFrameHandler getHandler(QuicContext context) {
        return new MaxStreamDataFrameHandler(context);
    }

    @Override
    public MaxStreamDataFrameSerializer getSerializer(QuicContext context) {
        return new MaxStreamDataFrameSerializer(this);
    }

    @Override
    public MaxStreamDataFramePreparator getPreparator(QuicContext context) {
        return new MaxStreamDataFramePreparator(context.getChooser(), this);
    }

    @Override
    public MaxStreamDataFrameParser getParser(QuicContext context, InputStream stream) {
        return new MaxStreamDataFrameParser(stream);
    }

    public ModifiableInteger getStreamId() {
        return streamId;
    }

    public void setStreamId(ModifiableInteger streamId) {
        this.streamId = streamId;
    }

    public void setStreamId(int streamId) {
        this.streamId = ModifiableVariableFactory.safelySetValue(this.streamId, streamId);
    }

    public ModifiableInteger getMaximumStreamData() {
        return maximumStreamData;
    }

    public void setMaximumStreamData(ModifiableInteger maximumStreamData) {
        this.maximumStreamData = maximumStreamData;
    }

    public void setMaximumStreamData(int maximumStreamData) {
        this.maximumStreamData =
                ModifiableVariableFactory.safelySetValue(this.maximumStreamData, maximumStreamData);
    }

    public int getStreamIdConfig() {
        return streamIdConfig;
    }

    public void setStreamIdConfig(int streamIdConfig) {
        this.streamIdConfig = streamIdConfig;
    }

    public int getMaximumStreamDataConfig() {
        return maximumStreamDataConfig;
    }

    public void setMaximumStreamDataConfig(int maximumStreamDataConfig) {
        this.maximumStreamDataConfig = maximumStreamDataConfig;
    }
}
