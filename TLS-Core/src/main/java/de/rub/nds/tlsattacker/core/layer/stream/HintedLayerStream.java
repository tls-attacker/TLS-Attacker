/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.stream;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class HintedLayerStream extends InputStream {

    private final LayerProcessingHint hint;

    private final ProtocolLayer layer;

    private ByteArrayInputStream stream = new ByteArrayInputStream(new byte[0]);

    public HintedLayerStream(LayerProcessingHint hint, ProtocolLayer layer) {
        this.hint = hint;
        this.layer = layer;
    }

    @Override
    public int read() throws IOException {
        if (stream.available() > 0) {
            return stream.read();
        } else {
            byte[] data = layer.retrieveMoreData(hint);
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

    public byte readByte() throws IOException {
        return (byte) read();
    }

    public int readInt(int size) throws IOException {
        byte[] readChunk = readChunk(size);
        return ArrayConverter.bytesToInt(readChunk);
    }

    public LayerProcessingHint getHint() {
        return hint;
    }
}
