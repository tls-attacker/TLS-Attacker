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
import de.rub.nds.tlsattacker.transport.socket.SocketState;
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
                // cachedSocketState = SocketState.CLOSED;
                return new byte[0];
            }

        }
    }
}
