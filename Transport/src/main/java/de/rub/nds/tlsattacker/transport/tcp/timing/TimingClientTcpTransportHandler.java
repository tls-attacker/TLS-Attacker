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

public class TimingClientTcpTransportHandler extends ClientTcpTransportHandler
        implements TimeableTransportHandler {

    private Long measurement = null;
    private boolean prependEarlyReadData = false;
    private int earlyReadData = 0;

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
        // read will block until data is available
        earlyReadData = inStream.read();
        long endTime = System.nanoTime();
        measurement = (endTime - startTime);
        prependEarlyReadData = true;
    }

    @Override
    public byte[] fetchData() throws IOException {
        byte[] data = super.fetchData();
        if (!prependEarlyReadData) {
            return data;
        } else {
            byte[] dataWithEarlyReadByte = new byte[data.length + 1];
            dataWithEarlyReadByte[0] = (byte) earlyReadData;
            prependEarlyReadData = false;
            System.arraycopy(data, 0, dataWithEarlyReadByte, 1, data.length);
            return dataWithEarlyReadByte;
        }
    }

    @Override
    public Long getLastMeasurement() {
        return measurement;
    }
}
