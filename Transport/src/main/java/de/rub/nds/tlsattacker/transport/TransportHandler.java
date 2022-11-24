/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport;

import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected long timeout;

    protected long firstTimeout;

    private boolean firstReceived;

    protected OutputStream outStream;

    protected PushbackInputStream inStream;

    private boolean initialized = false;

    private final ConnectionEndType connectionEndType;

    protected SocketState cachedSocketState = null;

    /**
     * The network interface the TransportHandler connects to. If null, the interface is chosen
     * automatically.
     */
    protected NetworkInterface networkInterface;

    public TransportHandler(Connection con) {
        this.firstTimeout = con.getFirstTimeout();
        this.connectionEndType = con.getLocalConnectionEndType();
        this.timeout = con.getTimeout();
        this.networkInterface = con.getNetworkInterface();
    }

    public TransportHandler(
            long firstTimeout,
            long timeout,
            ConnectionEndType type,
            NetworkInterface networkInterface) {
        this.firstTimeout = firstTimeout;
        this.timeout = timeout;
        this.connectionEndType = type;
        this.networkInterface = networkInterface;
    }

    public TransportHandler(long firstTimeout, long timeout, ConnectionEndType type) {
        this.firstTimeout = firstTimeout;
        this.timeout = timeout;
        this.connectionEndType = type;
    }

    public abstract void closeConnection() throws IOException;

    public abstract void closeClientConnection() throws IOException;

    public ConnectionEndType getConnectionEndType() {
        return connectionEndType;
    }

    /**
     * Reads the specified amount of data from the stream
     *
     * @param amountOfData
     * @return
     */
    public byte[] fetchData(int amountOfData) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (int i = 0; i < amountOfData; i++) {
            try {
                final int byteRead = inStream.read();
                if (byteRead == -1) {
                    throw new EOFException(
                            String.format(
                                    "Encountered EOF after %d bytes while reading %d bytes of data",
                                    i, amountOfData));
                }
                outputStream.write(byteRead);
            } catch (IOException e) {
                if (outputStream.size() > 0) {
                    inStream.unread(outputStream.toByteArray());
                }
                throw e;
            }
        }
        return outputStream.toByteArray();
    }

    @SuppressWarnings({"checkstyle:EmptyCatchBlock", "CheckStyle"})
    public byte[] fetchData() throws IOException {
        if (firstReceived) {
            setTimeout(firstTimeout);
        } else {
            setTimeout(timeout);
        }
        firstReceived = false;
        try {
            if (inStream.available() != 0) {
                byte[] data = new byte[inStream.available()];
                inStream.read(data);
                return data;
            } else {
                int read = inStream.read();
                if (read != -1) {
                    ByteArrayOutputStream stream = new ByteArrayOutputStream();
                    stream.write(read);
                    if (inStream.available() > 0) {
                        byte[] data = new byte[inStream.available()];
                        inStream.read(data);
                        stream.write(data);
                    }
                    return stream.toByteArray();
                } else {
                    cachedSocketState = SocketState.CLOSED;
                    return new byte[0];
                }
            }
        } catch (SocketException E) {
            cachedSocketState = SocketState.SOCKET_EXCEPTION;
            return new byte[0];
        } catch (SocketTimeoutException E) {
            return new byte[0];
        }
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

    public abstract void preInitialize() throws IOException;

    public abstract void initialize() throws IOException;

    public boolean isInitialized() {
        return initialized;
    }

    public abstract boolean isClosed() throws IOException;

    public long getTimeout() {
        return timeout;
    }

    public abstract void setTimeout(long timeout);

    // TODO: Change UDP to packet based processing instead of having in/out streams
    public InputStream getInputStream() {
        return inStream;
    }

    public OutputStream getOutputStream() {
        return outStream;
    }
}
