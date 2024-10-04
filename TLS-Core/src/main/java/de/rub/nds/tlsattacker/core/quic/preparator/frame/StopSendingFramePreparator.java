/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.StopSendingFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StopSendingFramePreparator extends QuicFramePreparator<StopSendingFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StopSendingFramePreparator(Chooser chooser, StopSendingFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("STOP SENDING Frame");
        prepareStreamId(getObject());
        prepareApplicationProtocolErrorCode(getObject());
    }

    protected void prepareStreamId(StopSendingFrame frame) {
        frame.setStreamId(frame.getStreamIdConfig());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void prepareApplicationProtocolErrorCode(StopSendingFrame frame) {
        frame.setApplicationProtocolErrorCode(frame.getApplicationProtocolErrorCodeConfig());
        LOGGER.debug(
                "Application Protocol Error Code: {}",
                frame.getApplicationProtocolErrorCode().getValue());
    }
}
