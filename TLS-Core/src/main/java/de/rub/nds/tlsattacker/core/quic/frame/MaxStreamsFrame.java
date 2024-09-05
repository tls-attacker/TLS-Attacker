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
import de.rub.nds.tlsattacker.core.quic.handler.frame.QuicFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.QuicFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.QuicFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.QuicFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class MaxStreamsFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger maximumStreams;

    private int maximumStreamsConfig;

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
    public QuicFrameHandler getHandler(QuicContext context) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public QuicFrameSerializer getSerializer(QuicContext context) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public QuicFramePreparator getPreparator(QuicContext context) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public QuicFrameParser getParser(QuicContext context, InputStream stream) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
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
