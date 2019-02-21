/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.stream;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;

public class StreamTransportHandler extends TransportHandler {

    private final InputStream inputStream;

    private final OutputStream outputStream;

    private boolean closed = false;

    public StreamTransportHandler(long timeout, ConnectionEndType type, InputStream inputStream,
            OutputStream outputStream) {
        super(timeout, type);
        this.inputStream = inputStream;
        this.outputStream = outputStream;
    }

    @Override
    public void closeConnection() throws IOException {
        if (isInitialized()) {
            try {
                inputStream.close();
            } catch (IOException E) {
                throw new IOException("Could not close StreamTransportHandler");
            }

            try {
                inputStream.close();
            } catch (IOException E) {
                throw new IOException("Could not close StreamTransportHandler");
            }
        } else {
            throw new IOException("Could not close StreamTransportHandler. Not Initialised");
        }
        closed = true;
    }

    @Override
    public void initialize() throws IOException {
        setStreams(new PushbackInputStream(inputStream), outputStream);
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public boolean isClosed() throws IOException {
        return closed;
    }

    @Override
    public void closeClientConnection() throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
