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
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.PathResponseFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.PathResponseFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.PathResponseFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.PathResponseFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** A PATH_RESPONSE frame (type=0x1b) is sent in response to a PATH_CHALLENGE frame. */
@XmlRootElement
public class PathResponseFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableByteArray data;

    public static final int PATH_CHALLENGE_LENGTH = 8;

    public PathResponseFrame() {
        super(QuicFrameType.PATH_RESPONSE_FRAME);
    }

    @Override
    public PathResponseFrameHandler getHandler(QuicContext context) {
        return new PathResponseFrameHandler(context);
    }

    @Override
    public PathResponseFrameSerializer getSerializer(QuicContext context) {
        return new PathResponseFrameSerializer(this);
    }

    @Override
    public PathResponseFramePreparator getPreparator(QuicContext context) {
        return new PathResponseFramePreparator(context.getChooser(), this);
    }

    @Override
    public PathResponseFrameParser getParser(QuicContext context, InputStream stream) {
        return new PathResponseFrameParser(stream);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }
}
