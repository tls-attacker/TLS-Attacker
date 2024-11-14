/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.NewConnectionIdFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewConnectionIdFramePreparator extends QuicFramePreparator<NewConnectionIdFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewConnectionIdFramePreparator(Chooser chooser, NewConnectionIdFrame frame) {
        super(chooser, frame);
    }

    @Override
    public void prepare() {
        LOGGER.debug("NEW CONNECTION ID Frame");
        prepareSequenceNumber(getObject());
        prepareRetirePriorTo(getObject());
        prepareConnectionIdLength(getObject());
        prepareConnectionId(getObject());
        prepareStatelessResetToken(getObject());
    }

    protected void prepareSequenceNumber(NewConnectionIdFrame frame) {
        frame.setSequenceNumber(frame.getSequenceNumberConfig());
        LOGGER.debug("Sequence Number: {}", frame.getSequenceNumber().getValue());
    }

    protected void prepareRetirePriorTo(NewConnectionIdFrame frame) {
        frame.setRetirePriorTo(frame.getRetirePriorToConfig());
        LOGGER.debug("Retire Prior To: {}", frame.getRetirePriorTo().getValue());
    }

    protected void prepareConnectionIdLength(NewConnectionIdFrame frame) {
        frame.setConnectionIdLength(frame.getLengthConfig());
        LOGGER.debug("Length: {}", frame.getConnectionIdLength().getValue());
    }

    protected void prepareConnectionId(NewConnectionIdFrame frame) {
        frame.setConnectionId(frame.getConnectionIdConfig());
        LOGGER.debug("Connection ID: {}", frame.getConnectionId().getValue());
    }

    protected void prepareStatelessResetToken(NewConnectionIdFrame frame) {
        frame.setStatelessResetToken(frame.getStatelessResetTokenConfig());
        LOGGER.debug("Stateless Reset Token: {}", frame.getStatelessResetToken().getValue());
    }
}
