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

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class TransportHandler {

    protected int tlsTimeout;
    
    protected long lastSystemNano;

    protected long lastMeasurement;

    protected boolean measuringTiming;

    public abstract void closeConnection();

    public abstract byte[] fetchData() throws IOException;

    public abstract void initialize(String address, int port) throws IOException;

    public abstract void sendData(byte[] data) throws IOException;

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
