/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.ResetStreamFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ResetStreamFramePreparator extends QuicFramePreparator<ResetStreamFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ResetStreamFramePreparator(Chooser chooser, ResetStreamFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("RESET STREAM Frame");
        prepareStreamId(getObject());
        prepareApplicationProtocolErrorCode(getObject());
        prepareFinalSize(getObject());
    }

    protected void prepareStreamId(ResetStreamFrame frame) {
        frame.setStreamId(frame.getStreamIdConfig());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void prepareApplicationProtocolErrorCode(ResetStreamFrame frame) {
        frame.setApplicationProtocolErrorCode(frame.getApplicationProtocolErrorCodeConfig());
        LOGGER.debug(
                "Application Protocol Error Code: {}",
                frame.getApplicationProtocolErrorCode().getValue());
    }

    protected void prepareFinalSize(ResetStreamFrame frame) {
        frame.setFinalSize(frame.getFinalSizeConfig());
        LOGGER.debug("Final Size: {}", frame.getFinalSize().getValue());
    }
}
