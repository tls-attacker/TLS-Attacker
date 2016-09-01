/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.net.SocketException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Florian Pfützenreuter <Florian.Pfuetzenreuter@rub.de>
 */
public class UDPTransportHandler extends TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger(UDPTransportHandler.class);

    private static final int DEFAULT_TLS_TIMEOUT = 3000;

    private DatagramSocket datagramSocket;

    private final DatagramPacket receivedPacket = new DatagramPacket(new byte[65527], 65527);

    private DatagramPacket sentPacket;

    private long responseNanos = -1;

    public UDPTransportHandler() {
	timeout = DEFAULT_TLS_TIMEOUT;
    }

    @Override
    public void initialize(String remoteAddress, int remotePort) throws IOException {
	datagramSocket = new DatagramSocket();

	datagramSocket.setSoTimeout(DEFAULT_TLS_TIMEOUT);
	datagramSocket.connect(InetAddress.getByName(remoteAddress), remotePort);

	sentPacket = new DatagramPacket(new byte[0], 0, datagramSocket.getInetAddress(), datagramSocket.getPort());

	if (LOGGER.isDebugEnabled()) {
	    StringBuilder logOut = new StringBuilder();
	    logOut.append("Socket bound to \"");
	    logOut.append(datagramSocket.getLocalAddress().getCanonicalHostName());
	    logOut.append(":");
	    logOut.append(datagramSocket.getLocalPort());
	    logOut.append("\". Specified remote host and port: \"");
	    logOut.append(datagramSocket.getInetAddress().getCanonicalHostName());
	    logOut.append(":");
	    logOut.append(datagramSocket.getPort());
	    logOut.append("\".");
	    LOGGER.debug(logOut.toString());
	}
    }

    @Override
    public void sendData(byte[] data) throws IOException {
	sentPacket.setData(data, 0, data.length);
	datagramSocket.send(sentPacket);
    }

    @Override
    public byte[] fetchData() throws IOException {
	responseNanos = System.nanoTime();
	datagramSocket.receive(receivedPacket);
	responseNanos = System.nanoTime() - responseNanos;
	return Arrays.copyOfRange(receivedPacket.getData(), 0, receivedPacket.getLength());
    }

    @Override
    public void closeConnection() {
	datagramSocket.close();
	LOGGER.debug("Socket closed.");
    }

    @Override
    public void setTimeout(long tlsTimeout) {
	this.timeout = tlsTimeout;
	if (datagramSocket != null) {
	    try {
		datagramSocket.setSoTimeout((int) (this.timeout));
	    } catch (SocketException e) {
		LOGGER.debug("Failed to set socket timeout. Exception:\n{}", e.getMessage());
	    }
	}
    }

    public int getLocalPort() {
	return datagramSocket.getLocalPort();
    }

    public InetAddress getLocalAddress() {
	return datagramSocket.getLocalAddress();
    }

    public int getRemotePort() {
	return datagramSocket.getPort();
    }

    public InetAddress getRemoteAddress() {
	return datagramSocket.getInetAddress();
    }

    public long getResponseTimeNanos() {
	return responseNanos;
    }
}