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
import de.rub.nds.tlsattacker.core.quic.handler.frame.MaxStreamsFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.MaxStreamsFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.MaxStreamsFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.MaxStreamsFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class MaxStreamsFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger maximumStreams;

    private int maximumStreamsConfig;

    @SuppressWarnings("unused") // JAXB
    private MaxStreamsFrame() {}

    public MaxStreamsFrame(boolean isBidirectional) {
        if (isBidirectional) {
            setFrameType(QuicFrameType.MAX_STREAMS_BIDI_FRAME);
        } else {
            setFrameType(QuicFrameType.MAX_STREAMS_UNI_FRAME);
        }
    }

    public MaxStreamsFrame(boolean isBidirectional, int maximumStreamsConfig) {
        this(isBidirectional);
        this.maximumStreamsConfig = maximumStreamsConfig;
    }

    @Override
    public MaxStreamsFrameHandler getHandler(Context context) {
        return new MaxStreamsFrameHandler(context.getQuicContext());
    }

    @Override
    public MaxStreamsFrameSerializer getSerializer(Context context) {
        return new MaxStreamsFrameSerializer(this);
    }

    @Override
    public MaxStreamsFramePreparator getPreparator(Context context) {
        return new MaxStreamsFramePreparator(context.getChooser(), this);
    }

    @Override
    public MaxStreamsFrameParser getParser(Context context, InputStream stream) {
        return new MaxStreamsFrameParser(stream);
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
