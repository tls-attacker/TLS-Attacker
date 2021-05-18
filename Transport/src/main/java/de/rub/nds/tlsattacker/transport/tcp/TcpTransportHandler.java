/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.socket.SocketState;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

public abstract class TcpTransportHandler extends TransportHandler {

    protected Socket socket;

    protected Integer srcPort;

    protected Integer dstPort;

    public TcpTransportHandler(Connection con) {
        super(con);
    }

    public TcpTransportHandler(long firstTimeout, long timeout, ConnectionEndType type, boolean isInStreamTerminating) {
        super(firstTimeout, timeout, type, isInStreamTerminating);
    }

    public TcpTransportHandler(long firstTimeout, long timeout, ConnectionEndType type) {
        super(firstTimeout, timeout, type);
    }

    /**
     * Checks the current SocketState. NOTE: If you check the SocketState and Data is received during the Check the
     * current State of the TransportHandler will get messed up and an Exception will be thrown.
     *
     * @return The current SocketState
     */
    public SocketState getSocketState(boolean withTimeout) {
        try {
            if (inStream == null) {
                return SocketState.UNAVAILABLE;
            }
            if (inStream.available() > 0) {
                return SocketState.DATA_AVAILABLE;
            }

            if (withTimeout) {
                socket.setSoTimeout((int) timeout);
            } else {
                socket.setSoTimeout(1);
            }

            int read = inStream.read();
            socket.setSoTimeout(1);

            if (read == -1) {
                inStream.unread(-1);
                return SocketState.CLOSED;
            } else {
                return SocketState.DATA_AVAILABLE;
            }
        } catch (SocketTimeoutException ex) {
            return SocketState.UP;
        } catch (SocketException ex) {
            return SocketState.SOCKET_EXCEPTION;
        } catch (IOException ex) {
            return SocketState.IO_EXCEPTION;
        }
    }

    public SocketState getSocketState() {
        return getSocketState(false);
    }

    public abstract Integer getSrcPort();

    public abstract void setSrcPort(int port);

    public abstract Integer getDstPort();

    public abstract void setDstPort(int port);
}
