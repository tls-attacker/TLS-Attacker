/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.stream;

import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;

/**
 * @author ic0ns
 */
public class TimeoutableInputStream extends InputStream {

    private InputStream stream;

    private long timeout;

    public TimeoutableInputStream(InputStream stream, long timeout) {
        this.stream = stream;
        this.timeout = timeout;
    }

    @Override
    public int read() throws IOException {
        long start = System.currentTimeMillis();
        while (true) {
            if (stream.available() > 0) {
                return stream.read();
            } else {
                if (System.currentTimeMillis() > start + timeout) {
                    throw new SocketTimeoutException();
                } else {
                    try {
                        Thread.currentThread().sleep(5);
                    } catch (InterruptedException ex) {
                        throw new RuntimeException(ex);
                    }
                }
            }
        }
    }

    @Override
    public boolean markSupported() {
        return stream.markSupported();
    }

    @Override
    public synchronized void reset() throws IOException {
        stream.reset();
    }

    @Override
    public synchronized void mark(int i) {
        stream.mark(i);
    }

    @Override
    public void close() throws IOException {
        stream.close();
    }

    @Override
    public int available() throws IOException {
        return stream.available();
    }

    @Override
    public long skip(long l) throws IOException {
        return stream.skip(l);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (off < 0 || len < 0 || b.length - off < len) {
            throw new IndexOutOfBoundsException();
        }

        int i, ch;
        for (i = 0; i < len; ++i)
            try {
                if ((ch = read()) < 0) {
                    return i == 0 ? -1 : i; // EOF
                }
                b[off + i] = (byte) ch;
            } catch (IOException ex) {
                // Only reading the first byte should cause an IOException.
                if (i == 0) {
                    throw ex;
                }
            }
        return i;
    }

    @Override
    public int read(byte[] bytes) throws IOException {
        return read(bytes, 0, bytes.length);
    }

    public long getTimeout() {
        return timeout;
    }

    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }
}
