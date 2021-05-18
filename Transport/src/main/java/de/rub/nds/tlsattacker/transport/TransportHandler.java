/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.SocketException;

public abstract class TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected long timeout;

    protected long firstTimeout;

    private boolean firstReceived;

    protected OutputStream outStream;

    protected PushbackInputStream inStream;

    private boolean initialized = false;

    private final ConnectionEndType type;

    /**
     * True {@link inStream} is expected to reach the End of Stream, meaning read will return -1.
     */
    private boolean isInStreamTerminating = true;

    public TransportHandler(Connection con) {
        this.firstTimeout = con.getFirstTimeout();
        this.type = con.getLocalConnectionEndType();
        this.timeout = con.getTimeout();
        this.isInStreamTerminating = false;
    }

    public TransportHandler(long firstTimeout, long timeout, ConnectionEndType type, boolean isInStreamTerminating) {
        this.firstTimeout = firstTimeout;
        this.timeout = timeout;
        this.type = type;
        this.isInStreamTerminating = isInStreamTerminating;
    }

    public TransportHandler(long firstTimeout, long timeout, ConnectionEndType type) {
        this.firstTimeout = firstTimeout;
        this.timeout = timeout;
        this.type = type;
    }

    public abstract void closeConnection() throws IOException;

    public abstract void closeClientConnection() throws IOException;

    /**
     * Reads the specified amount of data from the stream
     *
     * @param  amountOfData
     * @return
     */
    public byte[] fetchData(int amountOfData) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        for (int i = 0; i < amountOfData; i++) {
            stream.write(inStream.read());
        }
        return stream.toByteArray();
    }

    @SuppressWarnings({ "checkstyle:EmptyCatchBlock", "CheckStyle" })
    public byte[] fetchData() throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        long minTimeMillies = System.currentTimeMillis();
        if (firstReceived)
            minTimeMillies += timeout;
        else
            minTimeMillies += firstTimeout;
        while ((System.currentTimeMillis() < minTimeMillies) && (stream.toByteArray().length == 0)) {
            if (inStream.available() != 0) {
                while (inStream.available() != 0) {
                    int read = inStream.read();
                    stream.write(read);
                }
            } else {
                if (isInStreamTerminating) {
                    try {
                        // don't ask - the java api does not allow this
                        // otherwise...
                        Thread.sleep(1);
                        int read = inStream.read();
                        if (read == -1) {
                            // TCP FIN
                            firstReceived = true;
                            return stream.toByteArray();
                        }
                        inStream.unread(read);

                    } catch (SocketException e) {
                        // TCP RST received
                        firstReceived = true;
                        return stream.toByteArray();
                    } catch (Exception _) {
                    }
                }
            }
        }
        firstReceived = true;
        return stream.toByteArray();
    }

    public void sendData(byte[] data) throws IOException {
        if (!initialized) {
            throw new IOException("Transport handler is not initialized!");
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

    public final void setIsInStreamTerminating(boolean isInStreamTerminating) {
        this.isInStreamTerminating = isInStreamTerminating;
    }

    public final boolean isIsInStreamTerminating() {
        return isInStreamTerminating;
    }
}
