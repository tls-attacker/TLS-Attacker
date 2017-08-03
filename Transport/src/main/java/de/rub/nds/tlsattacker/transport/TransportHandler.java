/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

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

    public TransportHandler(long timeout) {
        this.timeout = timeout;
    }

    public abstract void closeConnection();

    public byte[] fetchData() throws IOException {
        if (!initialized) {
            throw new IOException("Transporthandler is not initalized!");
        }
        int available;
        long startTime = System.currentTimeMillis();
        do {
            available = inStream.available();
        } while (available == 0 && startTime + timeout < System.currentTimeMillis());
        byte[] receivedBytes = new byte[available];
        inStream.read(receivedBytes);
        return receivedBytes;
    }
    
    public void sendData(byte[] data) throws IOException {
        outStream.write(data);
        outStream.flush();
     }
 

    public void setStreams(InputStream inStream, OutputStream outStream) {
        this.outStream = outStream;
        this.inStream = inStream;
        initialized = true;
    }

    public abstract void initialize() throws IOException;
}
