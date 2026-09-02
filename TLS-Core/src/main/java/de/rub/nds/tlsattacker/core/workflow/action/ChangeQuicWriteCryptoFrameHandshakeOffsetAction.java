/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ChangeQuicWriteCryptoFrameHandshakeOffsetAction
        extends ChangeQuicWriteCryptoFrameOffsetAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChangeQuicWriteCryptoFrameHandshakeOffsetAction() {}

    public ChangeQuicWriteCryptoFrameHandshakeOffsetAction(long writeCryptoFrameOffset) {
        super(writeCryptoFrameOffset);
    }

    @Override
    protected void changeWriteCryptoFrameOffset(QuicContext quicContext) {
        LOGGER.info("Changed handshake write crypto frame offset");
        if (quicContext.getQuicFrameLayer() != null) {
            quicContext
                    .getQuicFrameLayer()
                    .setHandshakePhaseWriteCryptoFrameOffset(writeCryptoFrameOffset);
        }
    }
}
