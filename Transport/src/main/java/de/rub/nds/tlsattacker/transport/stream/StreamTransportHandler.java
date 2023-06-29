/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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

    private final TimeoutableInputStream timeoutableInputStream;

    private boolean closed = false;

    public StreamTransportHandler(
            long firstTimeout,
            long timeout,
            ConnectionEndType type,
            InputStream inputStream,
            OutputStream outputStream) {
        super(firstTimeout, timeout, type);
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        timeoutableInputStream = new TimeoutableInputStream(inputStream, timeout);
    }

    @Override
    public void closeConnection() throws IOException {
        if (isInitialized()) {
            try {
                timeoutableInputStream.close();
            } catch (IOException e) {
                throw new IOException("Could not close StreamTransportHandler");
            }

            try {
                timeoutableInputStream.close();
            } catch (IOException e) {
                throw new IOException("Could not close StreamTransportHandler");
            }
        } else {
            throw new IOException("Could not close StreamTransportHandler. Not Initialised");
        }
        closed = true;
    }

    @Override
    public void preInitialize() throws IOException {
        // nothing to do here
    }

    @Override
    public void initialize() throws IOException {
        cachedSocketState = null;
        setStreams(new PushbackInputStream(timeoutableInputStream), outputStream);
    }

    public InputStream getInputStream() {
        return timeoutableInputStream;
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

    @Override
    public void setTimeout(long timeout) {
        this.timeout = timeout;
        timeoutableInputStream.setTimeout(timeout);
    }
}
