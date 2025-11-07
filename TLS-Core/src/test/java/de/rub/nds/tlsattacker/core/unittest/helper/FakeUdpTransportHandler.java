/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class FakeUdpTransportHandler extends UdpTransportHandler implements FakeTransportHandler {

    private SilentByteArrayOutputStream outputStream;

    private ByteArrayInputStream inputStream;

    private Boolean opened = false;

    public FakeUdpTransportHandler(ConnectionEndType type) {
        super(0, type);
        inputStream = new ByteArrayInputStream(new byte[0]);
        outputStream = new SilentByteArrayOutputStream();
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
    public void preInitialize() {}

    public OutputStream getOutputStream() {
        return outputStream;
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public void resetOutputStream() {
        outputStream = new SilentByteArrayOutputStream();
    }
}
