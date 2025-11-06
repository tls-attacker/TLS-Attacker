/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.handler.frame;

import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.IOException;

public class ConnectionCloseFrameHandler extends QuicFrameHandler<ConnectionCloseFrame> {

    public ConnectionCloseFrameHandler(QuicContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(ConnectionCloseFrame frame) {
        quicContext.setReceivedConnectionCloseFrame(frame);
        // Kill connection in case of a TLS Alert
        if (quicContext.getConfig().getQuicImmediateCloseOnTlsError()
                && frame.getErrorCode().getValue() > 0x0100
                && frame.getErrorCode().getValue() < 0x01ff) {
            try {
                quicContext.getTransportHandler().closeConnection();
            } catch (IOException e) {
                throw new RuntimeException();
            }
        }
    }
}
