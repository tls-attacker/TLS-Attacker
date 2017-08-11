/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class TransportHandler {

    protected static final Logger LOGGER = LogManager.getLogger("Transport");

    protected long timeout;

    private OutputStream outStream;

    private InputStream inStream;

    private boolean initialized = false;

    private final ConnectionEndType type;

    public TransportHandler(long timeout, ConnectionEndType type) {
        this.timeout = timeout;
        this.type = type;
    }

    public abstract void closeConnection();

    public byte[] fetchData() throws IOException {
        byte[] response = new byte[0];

        long minTimeMillies = System.currentTimeMillis() + timeout;
        // long maxTimeMillies = System.currentTimeMillis() + timeout;
        while ((System.currentTimeMillis() < minTimeMillies) && (response.length == 0)) {
            // while ((System.currentTimeMillis() < maxTimeMillies) &&
            // (bis.available() != 0)) {
            while (inStream.available() != 0) {
                // TODO: It is never correct to use the return value of this
                // method to allocate a buffer intended to hold all data in this
                // stream.
                // http://docs.oracle.com/javase/7/docs/api/java/io/InputStream.html#available%28%29
                byte[] current = new byte[inStream.available()];
                int readResult = inStream.read(current);
                if (readResult != -1) {
                    response = ArrayConverter.concatenate(response, current);
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException ex) {

                    }
                }
            }
        }
        return response;
    }

    public void sendData(byte[] data) throws IOException {
        if (!initialized) {
            throw new IOException("Transporthandler is not initalized!");
        }
        outStream.write(data);
        outStream.flush();
    }

    protected final void setStreams(InputStream inStream, OutputStream outStream) {
        this.outStream = outStream;
        this.inStream = inStream;
        initialized = true;
    }

    public abstract void initialize() throws IOException;

    public boolean isInitialized() {
        return initialized;
    }

    public long getTimeout() {
        return timeout;
    }

    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }
}
