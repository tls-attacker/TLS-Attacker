/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.MaxStreamDataFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MaxStreamDataFramePreparator extends QuicFramePreparator<MaxStreamDataFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public MaxStreamDataFramePreparator(Chooser chooser, MaxStreamDataFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("MAX STREAM DATA Frame");
        prepareStreamId(getObject());
        prepareMaximumStreams(getObject());
    }

    protected void prepareStreamId(MaxStreamDataFrame frame) {
        frame.setStreamId(frame.getStreamIdConfig());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void prepareMaximumStreams(MaxStreamDataFrame frame) {
        frame.setMaximumStreamData(frame.getMaximumStreamDataConfig());
        LOGGER.debug("Maximum Stream Data: {}", frame.getMaximumStreamData().getValue());
    }
}
