/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.mockito.Mockito.*;

public class FakeTransportHandler extends TcpTransportHandler {
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
    public byte[] fetchData() throws IOException {
        byte[] answer = fetchableByte;
        fetchableByte = new byte[0];
        return answer;
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        sendByte = data;
    }

    @Override
    public void initialize() throws IOException {
        opened = true;
    }

    @Override
    public boolean isClosed() throws IOException {
        return !opened;
    }

    @Override
    public void closeClientConnection() throws IOException {
        if (!isClosed())
            opened = false;
    }

    @Override
    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    @Override
    public void preInitialize() throws IOException {
    }

    @Override
    public Integer getSrcPort() {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
                                                                       // Tools | Templates.
    }

    @Override
    public void setSrcPort(int port) {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
                                                                       // Tools | Templates.
    }

    @Override
    public Integer getDstPort() {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
                                                                       // Tools | Templates.
    }

    @Override
    public void setDstPort(int port) {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
                                                                       // Tools | Templates.
    }

    @Override
    public Socket getSocket() {
        Socket socket = mock(Socket.class);
        try {
            when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(fetchableByte));
            when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        } catch (IOException ex) {
            Logger.getLogger(FakeTransportHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return socket;
    }

}
