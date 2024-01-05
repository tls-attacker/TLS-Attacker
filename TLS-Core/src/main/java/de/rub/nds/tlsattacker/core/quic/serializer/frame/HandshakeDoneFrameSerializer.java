/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.frame.HandshakeDoneFrame;

public class HandshakeDoneFrameSerializer extends QuicFrameSerializer<HandshakeDoneFrame> {

    public HandshakeDoneFrameSerializer(HandshakeDoneFrame frame) {
        super(frame);
    }
}
