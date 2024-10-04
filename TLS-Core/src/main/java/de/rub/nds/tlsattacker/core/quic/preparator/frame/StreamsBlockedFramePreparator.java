/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.StreamsBlockedFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StreamsBlockedFramePreparator extends QuicFramePreparator<StreamsBlockedFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StreamsBlockedFramePreparator(Chooser chooser, StreamsBlockedFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("STREAMS BLOCKED Frame");
        prepareMaximumStreams(getObject());
    }

    protected void prepareMaximumStreams(StreamsBlockedFrame frame) {
        frame.setMaximumStreams(frame.getMaximumStreamsConfig());
        LOGGER.debug("Maximum Streams: {}", frame.getMaximumStreams().getValue());
    }
}
