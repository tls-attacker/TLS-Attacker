/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.frame;

import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.PaddingFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.PaddingFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.PaddingFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.PaddingFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * A PADDING frame (type=0x00) has no semantic value. PADDING frames can be used to increase the
 * size of a packet. Padding can be used to increase an Initial packet to the minimum required size
 * or to provide protection against traffic analysis for protected packets.
 */
@XmlRootElement
public class PaddingFrame extends QuicFrame {

    private int length;

    public PaddingFrame() {
        super(QuicFrameType.PADDING_FRAME);
        ackEliciting = false;
    }

    public PaddingFrame(int length) {
        this();
        this.length = length;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    @Override
    public PaddingFrameHandler getHandler(QuicContext context) {
        return new PaddingFrameHandler(context);
    }

    @Override
    public PaddingFrameSerializer getSerializer(QuicContext context) {
        return new PaddingFrameSerializer(this);
    }

    @Override
    public PaddingFramePreparator getPreparator(QuicContext context) {
        return new PaddingFramePreparator(context.getChooser(), this);
    }

    @Override
    public PaddingFrameParser getParser(QuicContext context, InputStream stream) {
        return new PaddingFrameParser(stream);
    }
}
