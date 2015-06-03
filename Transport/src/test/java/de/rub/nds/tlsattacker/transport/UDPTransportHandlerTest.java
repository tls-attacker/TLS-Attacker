/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Florian Pfützenreuter
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.transport;

import de.rub.nds.tlsattacker.util.RandomHelper;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Florian Pfützenreuter <Florian.Pfuetzenreuter@rub.de>
 */
public class UDPTransportHandlerTest {
    
    private final InetAddress localhost = InetAddress.getLoopbackAddress();

    public UDPTransportHandlerTest() {

    }

    @Test
    public void testSendData() throws Exception {
	UDPTransportHandler udpTH = new UDPTransportHandler();
	DatagramSocket testSocket = new DatagramSocket();
	testSocket.setSoTimeout(1000);

	udpTH.initialize(localhost.getHostName(), testSocket.getLocalPort());

	byte[] txData = new byte[8192];
	RandomHelper.getRandom().nextBytes(txData);
        byte[] rxData = new byte[8192];
	DatagramPacket rxPacket = new DatagramPacket(rxData, rxData.length,
                localhost, testSocket.getLocalPort());
        
	udpTH.sendData(txData);
	testSocket.receive(rxPacket);

	assertEquals("Confirm size of the sent data",
                txData.length, rxPacket.getLength());
	assertArrayEquals("Confirm sent data equals received data",
                txData, rxPacket.getData());
        
        udpTH.closeConnection();
        testSocket.close();
    }

    @Test
    public void testFetchData() throws Exception {
        UDPTransportHandler udpTH = new UDPTransportHandler();
        DatagramSocket testSocket = new DatagramSocket();
        
        udpTH.initialize(localhost.getHostName(), testSocket.getLocalPort());
        testSocket.connect(localhost, udpTH.getLocalPort());
        
        byte[] txData = new byte[8192];
        RandomHelper.getRandom().nextBytes(txData);
        DatagramPacket txPacket = new DatagramPacket(txData, txData.length,
                localhost, udpTH.getLocalPort());
        
        testSocket.send(txPacket);
        byte[] rxData = udpTH.fetchData();
        
        assertEquals("Confirm size of the received data",
                txData.length, rxData.length);
        assertArrayEquals("Confirm received data equals sent data",
                txData, rxData);
        
        udpTH.closeConnection();
        testSocket.close();        
    }
}