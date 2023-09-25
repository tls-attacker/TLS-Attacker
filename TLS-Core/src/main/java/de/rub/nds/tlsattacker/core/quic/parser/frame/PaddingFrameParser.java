/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.PaddingFrame;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

public class PaddingFrameParser extends QuicFrameParser<PaddingFrame> {

    public PaddingFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(PaddingFrame frame) {
        int length = 0;
        while (true) {
            try {
                if (this.getStream().available() == 0) {
                    break;
                }
                byte[] bytes = this.getStream().readNBytes(1);
                if (bytes[0] != 0) {
                    ((PushbackInputStream) this.getStream()).unread(bytes);
                    break;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            length++;
        }
        frame.setLength(length);
    }
}
