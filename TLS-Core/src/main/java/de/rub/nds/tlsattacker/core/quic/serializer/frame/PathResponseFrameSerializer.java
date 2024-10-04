/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.frame.PathResponseFrame;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PathResponseFrameSerializer extends QuicFrameSerializer<PathResponseFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PathResponseFrameSerializer(PathResponseFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeData();
        return getAlreadySerialized();
    }

    protected void writeData() {
        appendBytes(frame.getData().getValue());
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
