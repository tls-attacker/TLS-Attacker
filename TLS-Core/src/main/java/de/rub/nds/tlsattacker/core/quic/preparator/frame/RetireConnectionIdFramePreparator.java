/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.RetireConnectionIdFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RetireConnectionIdFramePreparator
        extends QuicFramePreparator<RetireConnectionIdFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RetireConnectionIdFramePreparator(Chooser chooser, RetireConnectionIdFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("RETIRE CONNECTION ID Frame");
        prepareSequenceNumber(getObject());
    }

    protected void prepareSequenceNumber(RetireConnectionIdFrame frame) {
        frame.setSequenceNumber(frame.getSequenceNumberConfig());
        LOGGER.debug("SequenceNumber: {}", frame.getSequenceNumber().getValue());
    }
}
