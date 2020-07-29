/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

import de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
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

    private final ConnectionEndType type;

    protected int srcPort;

    protected int dstPort;

    /**
     * True {@link inStream} is expected to reach the End of Stream, meaning
     * read will return -1.
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
     * @param amountOfData
     * @return
     */
    public byte[] fetchData(int amountOfData) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        for (int i = 0; i < amountOfData; i++) {
            stream.write(inStream.read());
        }
        return stream.toByteArray();
    }

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
                        // dont ask - the java api does not allow this
                        // otherwise...
                        Thread.sleep(1);
                        int read = inStream.read();
                        if (read == -1) {
                            // TCP FIN
                            firstReceived = true;
                            return stream.toByteArray();
                        }
                        inStream.unread(read);

                    } catch (SocketException E) {
                        // TCP RST received
                        firstReceived = true;
                        return stream.toByteArray();
                    } catch (Exception E) {
                    }
                }
            }
        }
        firstReceived = true;
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

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setIsInStreamTerminating(boolean isInStreamTerminating) {
        this.isInStreamTerminating = isInStreamTerminating;
    }

    public boolean isIsInStreamTerminating() {
        return isInStreamTerminating;
    }


    /**
     * Checks the current SocketState. NOTE: If you check the SocketState and
     * Data is received during the Check the current State of the
     * TransportHandler will get messed up and an Exception will be thrown.
     *
     * @return The current SocketState
     * @throws de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException
     */
    protected SocketState getTcpSocketState(Socket socket, boolean withTimeout) throws InvalidTransportHandlerStateException {
        try {
            if (inStream.available() > 0) {
                return SocketState.DATA_AVAILABLE;
            }

            if (!withTimeout) {
                socket.setSoTimeout(1);
            } else {
                socket.setSoTimeout((int) timeout);
            }

            int read = inStream.read();
            socket.setSoTimeout(1);

            if (read == -1) {
                inStream.unread(-1);
                return SocketState.CLOSED;
            } else {
                throw new InvalidTransportHandlerStateException("Received Data during SocketState check");
            }
        } catch (SocketTimeoutException ex) {
            return SocketState.TIMEOUT;
        } catch (SocketException ex) {
            return SocketState.SOCKET_EXCEPTION;
        } catch (IOException ex) {
            return SocketState.IO_EXCEPTION;
        }
    }
}
