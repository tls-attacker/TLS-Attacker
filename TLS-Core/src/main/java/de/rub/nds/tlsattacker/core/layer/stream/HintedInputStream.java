/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.stream;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import java.io.IOException;
import java.io.InputStream;

/**
 * InputStream that contains a LayerProcessingHint. Also provides methods useful when parsing data
 * from byteArrays.
 */
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
        if (size < 0 || size > 4) {
            throw new ParserException("Cannot read Integer of size " + size);
        }
        byte[] readChunk = readChunk(size);
        return ArrayConverter.bytesToInt(readChunk);
    }

    public byte[] readChunk(int size) throws IOException {
        if (size == 0) {
            return new byte[0];
        }
        byte[] chunk = new byte[size];
        int read = read(chunk);
        if (read != size) {
            throw new EndOfStreamException(
                    "Could not read "
                            + size
                            + " bytes from the stream. Only "
                            + read
                            + " bytes available");
        }
        return chunk;
    }

    protected abstract InputStream getDataSource();

    public abstract void extendStream(byte[] bytes);

    public void setHint(LayerProcessingHint hint) {
        this.hint = hint;
    }
}
