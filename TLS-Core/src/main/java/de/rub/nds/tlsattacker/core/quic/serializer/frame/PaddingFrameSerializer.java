/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.frame.PaddingFrame;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingFrameSerializer extends QuicFrameSerializer<PaddingFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PaddingFrameSerializer(PaddingFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writePadding();
        return getAlreadySerialized();
    }

    protected void writePadding() {
        appendBytes(new byte[frame.getLength()]);
        LOGGER.debug("Padding: {}", new byte[frame.getLength()]);
    }
}
