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
import java.util.logging.Level;
import java.util.logging.Logger;

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
            layer.receiveMoreDataForHint(getHint());
            // either the stream is now filled, or we ran into a timeout
            // or the next stream is available
            return stream.read();
        }
    }

    /**
     * Blocking read till either an exception is thrown or data is available
     */
//    public byte[] readChunk() throws IOException {
//        if (stream.available() != 0) {
//            byte[] data = new byte[stream.available()];
//            stream.read(data);
//            return data;
//
//        } else {
//            int read = stream.read();
//            if (read != -1) {
//                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//                outputStream.write(read);
//                if (stream.available() > 0) {
//                    byte[] data = new byte[stream.available()];
//                    stream.read(data);
//                    outputStream.write(data);
//                }
//                return outputStream.toByteArray();
//            } else {
//                return new byte[0];
//            }
//
//        }
//    }
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
            // we might be on a higher layer so there might actually be more data
            // available, but we do not know until we check

            // Check that we are not the bottom layer, if we are there is nothing more to do
            if (layer.getLowerLayer() != null) {
                layer.receiveMoreDataForHint(getHint());
                return stream.available();
            }
            return 0;
        }
    }

    @Override
    protected InputStream getDataSource() {
        return stream;
    }

    @Override
    public void extendStream(byte[] bytes) {
        try {
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();

            byte[] data = new byte[stream.available()];
            stream.read(data);
            outStream.write(data);
            outStream.write(bytes);
            stream = new ByteArrayInputStream(outStream.toByteArray());
        } catch (IOException ex) {
            throw new RuntimeException("IO Exception from ByteArrayStream");
        }
    }
}
