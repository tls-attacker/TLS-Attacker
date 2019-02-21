/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected long timeout;

    protected OutputStream outStream;

    protected PushbackInputStream inStream;

    private boolean initialized = false;

    private final ConnectionEndType type;

    public TransportHandler(long timeout, ConnectionEndType type) {
        this.timeout = timeout;
        this.type = type;
    }

    public abstract void closeConnection() throws IOException;

    public abstract void closeClientConnection() throws IOException;

    public byte[] fetchData() throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        long minTimeMillies = System.currentTimeMillis() + timeout;
        while ((System.currentTimeMillis() < minTimeMillies) && (stream.toByteArray().length == 0)) {
            if (inStream.available() != 0) {
                while (inStream.available() != 0) {
                    int read = inStream.read();
                    stream.write(read);
                }
            } else {
                try {
                    // dont ask - the java api does not allow this otherwise...
                    Thread.currentThread().sleep(1);
                    int read = inStream.read();
                    if (read == -1) {
                        // TCP FIN
                        return stream.toByteArray();
                    }
                    inStream.unread(read);

                } catch (SocketException E) {
                    // TCP RST received
                    return stream.toByteArray();
                } catch (Exception E) {
                }

            }
        }
        return stream.toByteArray();
    }

    public void sendData(byte[] data) throws IOException {
        if (!initialized) {
            throw new IOException("Transporthandler is not initalized!");
        }
        outStream.write(data);
        outStream.flush();
    }

    protected final void setStreams(PushbackInputStream inStream, OutputStream outStream) {
        this.outStream = outStream;
        this.inStream = inStream;
        initialized = true;
    }

    public abstract void initialize() throws IOException;

    public boolean isInitialized() {
        return initialized;
    }

    public abstract boolean isClosed() throws IOException;

    public long getTimeout() {
        return timeout;
    }

    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }
}
