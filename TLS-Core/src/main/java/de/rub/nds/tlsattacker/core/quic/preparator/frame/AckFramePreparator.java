/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.AckFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class AckFramePreparator extends QuicFramePreparator<AckFrame> {

    public AckFramePreparator(Chooser chooser, AckFrame object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {}
}