/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class SimpleTransportHandler extends TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger(SimpleTransportHandler.class);

    /**
     * min number of milliseconds to wait for a response to come
     */
    private static final int DEFAULT_TLS_TIMEOUT = 400;

    private Socket socket;

    private ServerSocket serverSocket;

    private boolean isServer = false;

    private BufferedOutputStream bos;

    private BufferedInputStream bis;

    private byte[] readTimingData;

    public SimpleTransportHandler() {
        tlsTimeout = DEFAULT_TLS_TIMEOUT;
    }

    @Override
    public void initialize(String address, int port) throws IOException {
        if (address.equals("server")) {
            serverSocket = new ServerSocket(port);
            socket = serverSocket.accept();
            LOGGER.debug("Server");
            isServer = true;
        } else {
            socket = new Socket(address, port);
        }

        OutputStream os = socket.getOutputStream();
        bos = new BufferedOutputStream(os);

        InputStream is = socket.getInputStream();
        bis = new BufferedInputStream(is);
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        bos.write(data);
        try {
            // todo: this must be improved in the future versions, best approach
            // would be to execute JNI calls or to execute the calls over a
            // MitM server written in C
            if (measuringTiming) {
                byte[] tmp = new byte[2000];
                bos.flush();
                lastSystemNano = System.nanoTime();
                int read = bis.read(tmp);
                lastMeasurement = System.nanoTime() - lastSystemNano;
                readTimingData = Arrays.copyOf(tmp, read);
            } else {
                bos.flush();
            }
        } catch (SocketException ex) {
            // While connecting to a Java server, a "Connection reset" failure
            // was received.Connection reset means that a TCP packet with the
            // RST bit was received. The most common cause of this is an attempt
            // to send to a partner that has closed its socket
            LOGGER.debug("Connection reset was received by flushing the data. It is very probable that the peer"
                    + " closed the socket after the last data was written. Thus, simply ignore this failure");
        }
    }

    @Override
    public byte[] fetchData() throws IOException {
        byte[] response = new byte[0];
        if (measuringTiming) {
            measuringTiming = false;
            response = readTimingData;
        }
        long minTimeMillies = System.currentTimeMillis() + tlsTimeout;
        // long maxTimeMillies = System.currentTimeMillis() + timeout;
        while ((System.currentTimeMillis() < minTimeMillies) && (response.length == 0)) {
            // while ((System.currentTimeMillis() < maxTimeMillies) &&
            // (bis.available() != 0)) {
            while (bis.available() != 0) {
                // TODO: It is never correct to use the return value of this
                // method to allocate a buffer intended to hold all data in this
                // stream.
                // http://docs.oracle.com/javase/7/docs/api/java/io/InputStream.html#available%28%29
                byte[] current = new byte[bis.available()];
                int readResult = bis.read(current);
                if (readResult != -1) {
                    response = ArrayConverter.concatenate(response, current);
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException ex) {

                    }
                }
            }
        }
        // LOGGER.debug("Accepted new bytes from server: {}",
        // ArrayConverter.bytesToHexString(response));
        if (isServer) {
            LOGGER.debug("Accepted {} new bytes from client", response.length);
        } else {
            LOGGER.debug("Accepted {} new bytes from server", response.length);
        }
        if (response.length < 33) {
            LOGGER.debug(ArrayConverter.bytesToHexString(response));
        }
        return response;
    }

    @Override
    public void closeConnection() {
        try {
            if (bos != null) {
                bos.close();
            }
        } catch (IOException e) {
            LOGGER.debug(e);
        }
        try {
            if (bis != null) {
                bis.close();
            }
        } catch (IOException e) {
            LOGGER.debug(e);
        }
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            LOGGER.debug(e);
        }
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            LOGGER.debug(e);
        }
    }

    public int getTlsTimeout() {
        return tlsTimeout;
    }

    public void setTlsTimeout(int tlsTimeout) {
        this.tlsTimeout = tlsTimeout;
    }
}
