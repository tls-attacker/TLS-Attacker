/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp.timing;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TimeableTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.io.IOException;
import java.net.SocketTimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TimingClientTcpTransportHandler extends ClientTcpTransportHandler
        implements TimeableTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    private boolean measuringActive = true;
    private Long measurement = null;

    public TimingClientTcpTransportHandler(Connection connection) {
        super(connection);
    }

    public TimingClientTcpTransportHandler(
            long firstTimeout, long timeout, String hostname, int port) {
        super(firstTimeout, timeout, hostname, port);
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        long startTime = System.nanoTime();
        super.sendData(data);
        if (measuringActive) {
            // read will block until data is available
            int earlyReadData = -1;
            try {
                earlyReadData = inStream.read();
            } catch (SocketTimeoutException ex) {
                LOGGER.debug(
                        "Transport handler expected a reaction but none was observed within socket timeout. Measurement will be null.");
                // do not fail send action if our timeout is too conservative
                measurement = null;
                return;
            }
            if (earlyReadData != -1) {
                inStream.unread(earlyReadData);
            }
            long endTime = System.nanoTime();
            measurement = (endTime - startTime);
        }
    }

    @Override
    public Long getLastMeasurement() {
        return measurement;
    }

    @Override
    public boolean isMeasuringActive() {
        return measuringActive;
    }

    @Override
    public void setMeasuringActive(boolean measuringActive) {
        this.measuringActive = measuringActive;
    }
}
