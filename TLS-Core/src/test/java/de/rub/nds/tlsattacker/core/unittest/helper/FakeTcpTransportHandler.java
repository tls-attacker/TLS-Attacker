/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class FakeTcpTransportHandler extends TcpTransportHandler implements FakeTransportHandler {

    /** Data that will be returned on a fetchData() call */
    private ByteArrayOutputStream outputStream;

    private ByteArrayInputStream inputStream;

    private Boolean opened = false;

    public FakeTcpTransportHandler(ConnectionEndType type) {
        super(0, type);
        inputStream = new ByteArrayInputStream(new byte[0]);
        outputStream = new ByteArrayOutputStream();
    }

    public byte[] getSentBytes() {
        return outputStream.toByteArray();
    }

    public void setFetchableByte(byte[] fetchableByte) {
        inputStream = new ByteArrayInputStream(fetchableByte);
    }

    @Override
    public void closeConnection() {
        opened = false;
    }

    @Override
    public byte[] fetchData() throws IOException {
        byte[] data = new byte[inputStream.available()];
        inputStream.read(data);
        return data;
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        outputStream.write(data);
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
        if (!isClosed()) {
            opened = false;
        }
    }

    @Override
    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    @Override
    public void preInitialize() {}

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public InputStream getInputStream() {
        return inputStream;
    }

    @Override
    public Integer getDstPort() {
        return -1;
    }

    @Override
    public Integer getSrcPort() {
        return -1;
    }

    @Override
    public void setDstPort(int port) {
        // Nothing to do
    }

    @Override
    public void setSrcPort(int port) {
        // Nothing to do
    }

    @Override
    public void resetOutputStream() {
        outputStream = new ByteArrayOutputStream();
    }
}
