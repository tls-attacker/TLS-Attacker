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
import de.rub.nds.tlsattacker.core.quic.handler.frame.StreamsBlockedFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.StreamsBlockedFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.StreamsBlockedFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.StreamsBlockedFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class StreamsBlockedFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger maximumStreams;

    private int maximumStreamsConfig;

    @SuppressWarnings("unused") // JAXB
    private StreamsBlockedFrame() {}

    public StreamsBlockedFrame(boolean isBidirectional) {
        if (isBidirectional) {
            setFrameType(QuicFrameType.STREAMS_BLOCKED_BIDI_FRAME);
        } else {
            setFrameType(QuicFrameType.STREAMS_BLOCKED_UNI_FRAME);
        }
    }

    public StreamsBlockedFrame(boolean isBidirectional, int maximumStreamsConfig) {
        this(isBidirectional);
        this.maximumStreamsConfig = maximumStreamsConfig;
    }

    @Override
    public StreamsBlockedFrameHandler getHandler(QuicContext context) {
        return new StreamsBlockedFrameHandler(context);
    }

    @Override
    public StreamsBlockedFrameSerializer getSerializer(QuicContext context) {
        return new StreamsBlockedFrameSerializer(this);
    }

    @Override
    public StreamsBlockedFramePreparator getPreparator(QuicContext context) {
        return new StreamsBlockedFramePreparator(context.getChooser(), this);
    }

    @Override
    public StreamsBlockedFrameParser getParser(QuicContext context, InputStream stream) {
        return new StreamsBlockedFrameParser(stream);
    }

    public ModifiableInteger getMaximumStreams() {
        return maximumStreams;
    }

    public void setMaximumStreams(ModifiableInteger maximumStreams) {
        this.maximumStreams = maximumStreams;
    }

    public void setMaximumStreams(int maximumStreams) {
        this.maximumStreams =
                ModifiableVariableFactory.safelySetValue(this.maximumStreams, maximumStreams);
    }

    public int getMaximumStreamsConfig() {
        return maximumStreamsConfig;
    }

    public void setMaximumStreamsConfig(int maximumStreamsConfig) {
        this.maximumStreamsConfig = maximumStreamsConfig;
    }
}
