/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class TransportHandler {

    protected static final Logger LOGGER = LogManager.getLogger("Transport");

    protected int socketTimeout;

    protected long lastSystemNano;

    protected long lastMeasurement;

    protected boolean measuringTiming;

    protected ConnectionEnd end;

    protected String hostname;

    protected int port;

    public TransportHandler(String hostname, int port, ConnectionEnd end, int socketTimeout) {
        this.end = end;
        this.socketTimeout = socketTimeout;
        this.hostname = hostname;
        this.port = port;
    }

    public abstract void closeConnection();

    public abstract byte[] fetchData() throws IOException;

    public abstract void initialize() throws IOException;

    public abstract void sendData(byte[] data) throws IOException;

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    public void measureTiming(boolean b) {
        measuringTiming = b;
    }

    public long getLastMeasurement() {
        return lastMeasurement;
    }

    public boolean isMeasuringTiming() {
        return measuringTiming;
    }

}
