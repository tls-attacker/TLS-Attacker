package de.rub.nds.tlsattacker.transport;

import de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException;
import de.rub.nds.tlsattacker.transport.socket.SocketState;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

public abstract class TcpTransportHandler extends TransportHandler {
    protected Socket socket;

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
     * Checks the current SocketState. NOTE: If you check the SocketState and
     * Data is received during the Check the current State of the
     * TransportHandler will get messed up and an Exception will be thrown.
     *
     * @return The current SocketState
     */
    public SocketState getSocketState(boolean withTimeout) {
        try {
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
}
