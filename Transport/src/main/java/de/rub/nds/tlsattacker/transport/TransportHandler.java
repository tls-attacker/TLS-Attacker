/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport;

import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.io.IOException;

public abstract class TransportHandler {

    protected long timeout;

    protected boolean initialized = false;

    private final ConnectionEndType connectionEndType;

    protected SocketState cachedSocketState = null;

    protected boolean resetClientSourcePort = true;

    protected boolean useIpv6 = false;

    public TransportHandler(Connection con) {
        this.connectionEndType = con.getLocalConnectionEndType();
        this.timeout = con.getTimeout();
        this.useIpv6 = con.getUseIpv6();
    }

    public TransportHandler(long timeout, ConnectionEndType type) {
        this.timeout = timeout;
        this.connectionEndType = type;
    }

    public abstract void closeConnection() throws IOException;

    public abstract void closeClientConnection() throws IOException;

    public ConnectionEndType getConnectionEndType() {
        return connectionEndType;
    }

    public abstract void preInitialize() throws IOException;

    public abstract void initialize() throws IOException;

    public abstract void sendData(byte[] data) throws IOException;

    public abstract byte[] fetchData() throws IOException;

    public abstract byte[] fetchData(int amountOfData) throws IOException;

    public boolean isInitialized() {
        return initialized;
    }

    public abstract boolean isClosed() throws IOException;

    public long getTimeout() {
        return timeout;
    }

    public abstract void setTimeout(long timeout);

    public boolean isResetClientSourcePort() {
        return resetClientSourcePort;
    }

    public void setResetClientSourcePort(boolean resetClientSourcePort) {
        this.resetClientSourcePort = resetClientSourcePort;
    }

    public boolean isUseIpv6() {
        return useIpv6;
    }

    public void setUseIpv6(boolean useIpv6) {
        this.useIpv6 = useIpv6;
    }
}
