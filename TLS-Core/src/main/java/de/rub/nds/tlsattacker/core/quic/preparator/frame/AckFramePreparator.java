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
import de.rub.nds.tlsattacker.core.quic.frame.AckFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckFramePreparator extends QuicFramePreparator<AckFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AckFramePreparator(Chooser chooser, AckFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("ACK Frame");
        prepareLargestAcknowledged(getObject());
        prepareAckDelay(getObject());
        prepareAckRangeCount(getObject());
        prepareFirstAckRange(getObject());
        QuicFrameType frameType = QuicFrameType.getFrameType(getObject().getFrameType().getValue());
        if (frameType == QuicFrameType.ACK_FRAME_WITH_ECN) {
            prepareEcnCounts(getObject());
        }
    }

    protected void prepareLargestAcknowledged(AckFrame frame) {
        frame.setLargestAcknowledged(frame.getLargestAcknowledgedConfig());
        LOGGER.debug("Largest Acknowledged: {}", frame.getLargestAcknowledged().getValue());
    }

    protected void prepareAckDelay(AckFrame frame) {
        frame.setAckDelay(frame.getAckDelayConfig());
        LOGGER.debug("ACK Delay: {}", frame.getAckDelay().getValue());
    }

    protected void prepareAckRangeCount(AckFrame frame) {
        frame.setAckRangeCount(frame.getAckRangeCountConfig());
        LOGGER.debug("ACK Range Count: {}", frame.getAckRangeCount().getValue());
    }

    protected void prepareFirstAckRange(AckFrame frame) {
        frame.setFirstACKRange(frame.getFirstACKRangeConfig());
        LOGGER.debug("First ACK Range: {}", frame.getFirstACKRange().getValue());
    }

    protected void prepareEcnCounts(AckFrame frame) {
        frame.setEct0(frame.getEct0Config());
        LOGGER.debug("ECT0 Count: {}", frame.getEct0().getValue());
        frame.setEct1(frame.getEct1Config());
        LOGGER.debug("ECT1 Count: {}", frame.getEct1().getValue());
        frame.setEcnCe(frame.getEcnCeConfig());
        LOGGER.debug("ECT-CE Count: {}", frame.getEcnCe().getValue());
    }
}
