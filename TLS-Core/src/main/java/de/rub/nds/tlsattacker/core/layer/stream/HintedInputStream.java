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
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import java.io.IOException;
import java.io.InputStream;

public abstract class HintedInputStream extends InputStream {

    private LayerProcessingHint hint;

    public HintedInputStream(LayerProcessingHint hint) {
        this.hint = hint;
    }

    public LayerProcessingHint getHint() {
        return hint;
    }

    public byte readByte() throws IOException {
        return (byte) read();
    }

    public int readInt(int size) throws IOException {
        byte[] readChunk = readChunk(size);
        return ArrayConverter.bytesToInt(readChunk);
    }

    public byte[] readChunk(int size) throws IOException {
        byte[] chunk = new byte[size];
        int read = getDataSource().read(chunk);
        if (read != size) {
            throw new IOException(
                "Could not read " + size + " bytes from the stream. Only " + read + " bytes available");
        }
        return chunk;
    }

    protected abstract InputStream getDataSource();
}
