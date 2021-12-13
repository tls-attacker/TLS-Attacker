/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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

public class HintedLayerInputStream extends HintedInputStream {

    private final ProtocolLayer layer;

    private ByteArrayInputStream stream = new ByteArrayInputStream(new byte[0]);

    public HintedLayerInputStream(LayerProcessingHint hint, ProtocolLayer layer) {
        super(hint);
        this.layer = layer;
    }

    @Override
    public int read() throws IOException {
        if (stream.available() > 0) {
            return stream.read();
        } else {
            byte[] data = layer.retrieveMoreData(getHint());
            if (data != null) {
                stream = new ByteArrayInputStream(data);
                return this.read();
            } else {
                return -1;
            }
        }
    }

    /**
     * Blocking read till either an exception is thrown or data is available
     */
    public byte[] readChunk() throws IOException {
        if (stream.available() != 0) {
            byte[] data = new byte[stream.available()];
            stream.read(data);
            return data;

        } else {
            int read = stream.read();
            if (read != -1) {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(read);
                if (stream.available() > 0) {
                    byte[] data = new byte[stream.available()];
                    stream.read(data);
                    outputStream.write(data);
                }
                return outputStream.toByteArray();
            } else {
                return new byte[0];
            }

        }
    }

    public byte[] readChunk(int size) throws IOException {
        byte[] chunk = new byte[size];
        int read = stream.read(chunk);
        if (read != size) {
            throw new IOException(
                "Could not read " + size + " bytes from the stream. Only " + read + " bytes available");
        }
        return chunk;
    }

    @Override
    public int available() throws IOException {
        if (stream.available() > 0) {
            return stream.available();
        } else {
            if (layer.getLowerLayer() != null) {
                while (layer.getLowerLayer().getDataStream().available() > 0) {
                    byte[] data = layer.getLowerLayer().retrieveMoreData(getHint());
                    if (data != null) {
                        stream = new ByteArrayInputStream(data);
                    }
                    if (stream.available() > 0) {
                        return stream.available();
                    }
                }
            }
            return 0;
        }
    }

    @Override
    protected InputStream getDataSource() {
        return stream;
    }
}
