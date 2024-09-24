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
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionCloseFramePreparator extends QuicFramePreparator<ConnectionCloseFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ConnectionCloseFramePreparator(Chooser chooser, ConnectionCloseFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("CONNECTION CLOSE Frame");
        prepareErrorCode(getObject());
        QuicFrameType frameType = QuicFrameType.getFrameType(getObject().getFrameType().getValue());
        if (frameType == QuicFrameType.CONNECTION_CLOSE_QUIC_FRAME) {
            prepareFrameType(getObject());
        }
        prepareReasonPhraseLength(getObject());
        prepareReasonPhrase(getObject());
    }

    protected void prepareErrorCode(ConnectionCloseFrame frame) {
        frame.setErrorCode(frame.getErrorCodeConfig());
        LOGGER.debug("Error Code: {}", frame.getErrorCode().getValue());
    }

    protected void prepareFrameType(ConnectionCloseFrame frame) {
        frame.setTriggerFrameType(frame.getTriggerFrameTypeConfig());
        LOGGER.debug("Frame Type: {}", frame.getTriggerFrameType().getValue());
    }

    protected void prepareReasonPhraseLength(ConnectionCloseFrame frame) {
        frame.setReasonPhraseLength(frame.getReasonPhraseLengthConfig());
        LOGGER.debug("Reason Phrase Length: {}", frame.getReasonPhraseLength().getValue());
    }

    protected void prepareReasonPhrase(ConnectionCloseFrame frame) {
        frame.setReasonPhrase(frame.getReasonPhraseConfig());
        LOGGER.debug("Reason Phrase: {}", frame.getReasonPhrase().getValue());
    }
}
