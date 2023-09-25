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

public class NewConnectionIdFramePreparator extends QuicFramePreparator<NewConnectionIdFrame> {

    public NewConnectionIdFramePreparator(Chooser chooser, NewConnectionIdFrame frame) {
        super(chooser, frame);
    }

    @Override
    public void prepare() {}
}
