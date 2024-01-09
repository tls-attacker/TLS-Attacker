/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import java.net.SocketException;
import java.net.SocketTimeoutException;

public abstract class StreambasedTransportHandler extends TransportHandler {

    protected OutputStream outStream;

    protected PushbackInputStream inStream;

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

    public byte[] fetchData() throws IOException {
        setTimeout(timeout);
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

    // TODO: Change UDP to packet based processing instead of having in/out streams
    public InputStream getInputStream() {
        return inStream;
    }

    public OutputStream getOutputStream() {
        return outStream;
    }
}
