/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.PathResponseFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PathResponseFramePreparator extends QuicFramePreparator<PathResponseFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PathResponseFramePreparator(Chooser chooser, PathResponseFrame frame) {
        super(chooser, frame);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing PATH_RESPONSE Frame");
        prepareData(getObject());
    }

    protected void prepareData(PathResponseFrame frame) {
        if (!frame.isOverwritePathChallengeData()
                && chooser.getContext().getQuicContext().getPathChallengeData() != null) {
            frame.setData(chooser.getContext().getQuicContext().getPathChallengeData());
        } else if (frame.getData() == null) {
            frame.setData(chooser.getConfig().getDefaultQuicPathChallange());
        }
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
