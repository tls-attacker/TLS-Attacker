/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
public class UDPTransportHandler implements TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger(UDPTransportHandler.class);

    private static final int DEFAULT_RESPONSE_WAIT = 3000;

    private static final int DEFAULT_RECEIVE_BUFFER_SIZE = 1048576;

    private int maxResponseWait = DEFAULT_RESPONSE_WAIT;

    private DatagramSocket so;

    private InetAddress remoteAddress;

    private InetAddress localAddress;

    private int remotePort;

    private int localPort;

    /**
     * To avoid fragmentation, the size of any packet should ideally be smaller
     * or equal to the PMTU between two peers. In most ethernet or internet
     * environments the (P)MTU is 1500 bytes.
     * 
     * UDPs header consists of 8 bytes, while the typical IPv4 header is 20
     * bytes in size. This results in 1500 - 28 = 1472 bytes of payload per
     * packet. When in LAN environments that support Jumboframes the MTU is 9000
     * bytes, resulting in a payload size of 9000 - 28 = 8972 bytes.
     * 
     * TODO (future): PMTU discovery. Additional library like jNetPcap needed
     * (Java doesn't support ICMP or raw IP packets natively).
     */
    private final int mtu = 1500;

    @Override
    public void initialize(String remoteAddress, int remotePort) throws IOException {
	this.remoteAddress = InetAddress.getByName(remoteAddress);
	this.remotePort = remotePort;
	so = new DatagramSocket();
	so.setReceiveBufferSize(DEFAULT_RECEIVE_BUFFER_SIZE);
	so.setSoTimeout(DEFAULT_RESPONSE_WAIT);
	so.connect(this.remoteAddress, this.remotePort);
	localAddress = so.getLocalAddress();
	localPort = so.getLocalPort();
	LOGGER.debug("Socket bound to \"" + localAddress.getCanonicalHostName() + ":" + localPort
		+ "\". Specified remote host and port: \"" + this.remoteAddress.getCanonicalHostName() + ":"
		+ this.remotePort + "\".");
    }

    @Override
    public void sendData(byte[] data) throws IOException {
	so.send(new DatagramPacket(data, 0, data.length, remoteAddress, remotePort));
    }

    @Override
    public byte[] fetchData() throws IOException {
	// A packet buffer of 65527 bytes is enough to retain the largest
	// possible UDP packets in IPv4 and IPv6.
	byte[] buffer = new byte[65527];
	DatagramPacket rPacket = new DatagramPacket(buffer, buffer.length);
	so.receive(rPacket);
	// Function returns only the recieved packet, not the whole buffer
	return Arrays.copyOfRange(rPacket.getData(), 0, rPacket.getLength());
    }

    @Override
    public void closeConnection() {
	so.close();
	LOGGER.debug("Socket closed.");
    }

    public int getMaxResponseWait() {
	return maxResponseWait;
    }

    public void setMaxResponseWait(int maxResponseWait) {
	this.maxResponseWait = maxResponseWait;
	if (so != null) {
	    try {
		so.setSoTimeout(this.maxResponseWait);
	    } catch (SocketException e) {
		LOGGER.debug("Failed to set socket timeout. Exception:\n" + e.getMessage());
	    }
	}
    }

    public int getMTU() {
	return mtu;
    }

    public int getLocalPort() {
	return localPort;
    }
}