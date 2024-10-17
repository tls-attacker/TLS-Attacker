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
import de.rub.nds.tlsattacker.core.quic.handler.frame.HandshakeDoneFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.HandshakeDoneFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.HandshakeDoneFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.HandshakeDoneFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * The server uses a HANDSHAKE_DONE frame (type=0x1e) to signal confirmation of the handshake to the
 * client.
 */
@XmlRootElement
public class HandshakeDoneFrame extends QuicFrame {

    public HandshakeDoneFrame() {
        super(QuicFrameType.HANDSHAKE_DONE_FRAME);
    }

    @Override
    public HandshakeDoneFrameHandler getHandler(Context context) {
        return new HandshakeDoneFrameHandler(context.getQuicContext());
    }

    @Override
    public HandshakeDoneFrameSerializer getSerializer(Context context) {
        return new HandshakeDoneFrameSerializer(this);
    }

    @Override
    public HandshakeDoneFramePreparator getPreparator(Context context) {
        return new HandshakeDoneFramePreparator(context.getChooser(), this);
    }

    @Override
    public HandshakeDoneFrameParser getParser(Context context, InputStream stream) {
        return new HandshakeDoneFrameParser(stream);
    }
}
