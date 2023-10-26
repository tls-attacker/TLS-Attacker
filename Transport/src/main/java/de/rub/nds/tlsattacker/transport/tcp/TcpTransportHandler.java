/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TcpTransportHandler extends TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Socket socket;

    protected Integer srcPort;

    protected Integer dstPort;

    public TcpTransportHandler(Connection con) {
        super(con);
        srcPort = con.getSourcePort();
    }

    public TcpTransportHandler(long firstTimeout, long timeout, ConnectionEndType type) {
        super(firstTimeout, timeout, type);
    }

    /**
     * Checks the current SocketState. NOTE: If you check the SocketState and Data is received
     * during the Check the current State of the TransportHandler will get messed up and an
     * Exception will be thrown.
     *
     * @return The current SocketState
     */
    public SocketState getSocketState(boolean withTimeout) {
        try {
            if (cachedSocketState != null) {
                return cachedSocketState;
            }
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
            if (read == -1) {
                return SocketState.CLOSED;
            } else {
                inStream.unread(read);
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

    @Override
    public void setTimeout(long timeout) {
        try {
            this.timeout = timeout;
            socket.setSoTimeout((int) timeout);

        } catch (SocketException ex) {
            LOGGER.error("Could not adjust socket timeout", ex);
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
