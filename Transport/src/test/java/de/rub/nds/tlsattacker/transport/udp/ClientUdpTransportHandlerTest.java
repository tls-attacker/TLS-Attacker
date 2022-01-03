/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * <p>Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class ClientUdpTransportHandlerTest {

    private final InetAddress localhost = InetAddress.getLoopbackAddress();

    @Test
    public void testSendData() throws Exception {
        try (DatagramSocket testSocket = new DatagramSocket()) {
            ClientUdpTransportHandler udpTH =
                new ClientUdpTransportHandler(1, 1, localhost.getHostName(), testSocket.getLocalPort());

            udpTH.initialize();

            byte[] txData = new byte[8192];
            RandomHelper.getRandom().nextBytes(txData);
            byte[] rxData = new byte[8192];
            DatagramPacket rxPacket = new DatagramPacket(rxData, rxData.length, localhost, testSocket.getLocalPort());

            udpTH.sendData(txData);
            testSocket.receive(rxPacket);

            assertEquals("Confirm size of the sent data", txData.length, rxPacket.getLength());
            assertArrayEquals("Confirm sent data equals received data", txData, rxPacket.getData());

            udpTH.closeConnection();
        }
    }

    @Test
    public void testFetchData() throws Exception {
        try (DatagramSocket testSocket = new DatagramSocket()) {
            ClientUdpTransportHandler udpTH =
                new ClientUdpTransportHandler(1, 1, localhost.getHostName(), testSocket.getLocalPort());

            udpTH.initialize();
            testSocket.connect(localhost, udpTH.getSrcPort());
            udpTH.setTimeout(1);

            byte[] allSentData = new byte[0];
            byte[] allReceivedData = new byte[0];
            byte[] txData;
            byte[] rxData;
            DatagramPacket txPacket;
            int numTestPackets = 100;

            for (int i = 0; i < numTestPackets; i++) {
                txData = new byte[RandomHelper.getRandom().nextInt(16383) + 1];
                RandomHelper.getRandom().nextBytes(txData);
                txPacket = new DatagramPacket(txData, txData.length, localhost, udpTH.getSrcPort());
                testSocket.send(txPacket);
                allSentData = ArrayConverter.concatenate(allSentData, txData);
                rxData = udpTH.fetchData();
                allReceivedData = ArrayConverter.concatenate(allReceivedData, rxData);
            }
            assertEquals("Confirm size of the received data", allSentData.length, allReceivedData.length);
            assertArrayEquals("Confirm received data equals sent data", allSentData, allReceivedData);

            udpTH.closeConnection();
        }
    }

    @Test
    public void testFetchTimeout() throws Exception {
        ClientUdpTransportHandler udpTH = new ClientUdpTransportHandler(1, 1, localhost.getHostName(), 12345);
        udpTH.initialize();

        byte[] rxData;
        rxData = udpTH.fetchData();
        assertEquals(0, rxData.length);
        rxData = udpTH.fetchData();
        assertEquals(0, rxData.length);
        udpTH.closeConnection();

    }
}
