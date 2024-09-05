/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.PathChallengeFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PathChallengeFramePreparator extends QuicFramePreparator<PathChallengeFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PathChallengeFramePreparator(Chooser chooser, PathChallengeFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing PATH_CHALLANGE Frame");
        prepareData(getObject());
    }

    protected void prepareData(PathChallengeFrame frame) {
        frame.setData(chooser.getContext().getConfig().getDefaultQuicPathChallange());
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
