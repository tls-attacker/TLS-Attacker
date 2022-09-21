/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;

public class FakeTransportHandler extends TransportHandler {
    /**
     * Data that will be returned on a fetchData() call
     */
    private byte[] fetchableByte;
    private byte[] sendByte;
    private Boolean opened = false;

    public FakeTransportHandler(ConnectionEndType type) {
        super(0, 0, type);
        fetchableByte = new byte[0];
    }

    public byte[] getSendByte() {
        return sendByte;
    }

    public byte[] getFetchableByte() {
        return fetchableByte;
    }

    public void setFetchableByte(byte[] fetchableByte) {
        this.fetchableByte = fetchableByte;
    }

    @Override
    public void closeConnection() {
        opened = false;
    }

    @Override
    public byte[] fetchData() {
        byte[] answer = fetchableByte;
        fetchableByte = new byte[0];
        return answer;
    }

    @Override
    public void sendData(byte[] data) {
        sendByte = data;
    }

    @Override
    public void initialize() {
        opened = true;
    }

    @Override
    public boolean isClosed() {
        return !opened;
    }

    @Override
    public void closeClientConnection() {
        if (!isClosed())
            opened = false;
    }

    @Override
    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    @Override
    public void preInitialize() {
    }

}
