/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.frame.DatagramFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DatagramFramePreparator extends QuicFramePreparator<DatagramFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DatagramFramePreparator(Chooser chooser, DatagramFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("DATAGRAM Frame");
        QuicFrameType frameType = QuicFrameType.getFrameType(getObject().getFrameType().getValue());
        if (frameType == QuicFrameType.DATAGRAM_FRAME_LEN) {
            prepareLength(getObject());
        }
        prepareData(getObject());
    }

    protected void prepareLength(DatagramFrame frame) {
        frame.setLength(frame.getLengthConfig());
        LOGGER.debug("Length: {}", frame.getLength().getValue());
    }

    protected void prepareData(DatagramFrame frame) {
        frame.setData(frame.getDataConfig());
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
