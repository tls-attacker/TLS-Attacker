/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.stream;

import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;

import java.io.IOException;
import java.io.InputStream;

public class HintedInputStreamAdapterStream extends HintedInputStream {

    private InputStream stream;

    public HintedInputStreamAdapterStream(LayerProcessingHint hint, InputStream stream) {
        super(hint);
        this.stream = stream;
    }

    @Override
    protected InputStream getDataSource() {
        return stream;
    }

    @Override
    public int read() throws IOException {
        return stream.read();
    }

    @Override
    public int available() throws IOException {
        return stream.available();
    }

    @Override
    public void extendStream(byte[] bytes) {
        throw new UnsupportedOperationException("HintedInputStreamAdapterStream is not extendable.");
    }

}
