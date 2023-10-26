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

public class PathResponseFramePreparator extends QuicFramePreparator<PathResponseFrame> {

    public PathResponseFramePreparator(Chooser chooser, PathResponseFrame frame) {
        super(chooser, frame);
    }

    @Override
    public void prepare() {
        getObject().setData(chooser.getContext().getQuicContext().getPathChallengeData());
    }
}
