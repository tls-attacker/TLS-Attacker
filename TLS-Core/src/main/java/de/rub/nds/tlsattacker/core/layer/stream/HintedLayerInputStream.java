/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.stream;

import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * The HintedLayerInputStream is assigned to a layer. When reading data from it, the stream tries to
 * receive more data using the layer it is assigned to.
 */
public class HintedLayerInputStream extends HintedInputStream {

    private final ProtocolLayer layer;

    private ByteArrayInputStream stream = new ByteArrayInputStream(new byte[0]);

    public HintedLayerInputStream(LayerProcessingHint hint, ProtocolLayer layer) {
        super(hint);
        this.layer = layer;
    }

    /**
     * Return data from the underlaying stream. If none is present, write more data into the stream
     * using the layer.
     */
    @Override
    public int read() throws IOException {
        if (stream.available() > 0) {
            return stream.read();
        } else {
            layer.receiveMoreDataForHint(getHint());
            // either the stream is now filled, or we ran into a timeout
            // or the next stream is available
            return stream.read();
        }
    }

    @Override
    public int available() throws IOException {
        return stream.available();
    }

    @Override
    protected InputStream getDataSource() {
        return stream;
    }

    /** Extends the current data in the stream with the given data. */
    @Override
    public void extendStream(byte[] bytes) {
        try {
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();
            stream.transferTo(outStream);
            outStream.write(bytes);
            stream = new ByteArrayInputStream(outStream.toByteArray());
        } catch (IOException ex) {
            throw new RuntimeException("IO Exception from ByteArrayStream");
        }
    }
}
