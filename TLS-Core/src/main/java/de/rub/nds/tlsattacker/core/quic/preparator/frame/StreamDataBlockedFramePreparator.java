/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.StreamDataBlockedFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StreamDataBlockedFramePreparator extends QuicFramePreparator<StreamDataBlockedFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StreamDataBlockedFramePreparator(Chooser chooser, StreamDataBlockedFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("STREAMS DATA BLOCKED Frame");
        prepareStreamId(getObject());
        prepareMaximumStreams(getObject());
    }

    protected void prepareStreamId(StreamDataBlockedFrame frame) {
        frame.setStreamId(frame.getStreamIdConfig());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void prepareMaximumStreams(StreamDataBlockedFrame frame) {
        frame.setMaximumStreamData(frame.getMaximumStreamDataConfig());
        LOGGER.debug("Maximum Stream Data: {}", frame.getMaximumStreamData().getValue());
    }
}
