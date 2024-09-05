/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.NewTokenFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewTokenFramePreparator extends QuicFramePreparator<NewTokenFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewTokenFramePreparator(Chooser chooser, NewTokenFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing NEW_TOKEN Frame");
        prepareToken(getObject());
        prepareTokenLength(getObject());
    }

    protected void prepareToken(NewTokenFrame frame) {
        frame.setToken(chooser.getContext().getConfig().getDefaultQuicPathChallange());
        LOGGER.debug("Token: {}", frame.getToken().getValue());
    }

    protected void prepareTokenLength(NewTokenFrame frame) {
        frame.setTokenLength(frame.getToken().getValue().length);
        LOGGER.debug("Token Length: {}", frame.getTokenLength().getValue());
    }
}
