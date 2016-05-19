/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.eap;

import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.Scanner;
import java.util.concurrent.ArrayBlockingQueue;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * Networkhandler to open Interface, send/receive Frames on Data Link Layer,
 * close the connection
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class NetworkHandler {
    private static NetworkHandler networkhandler = new NetworkHandler();

    Pcap pcap;

    public byte[] dst_mac = EapConstants.BROADCAST_ADDRESS;

    public byte[] src_mac;

    public byte[] frametype = EapConstants.ETHERTYPE_EAP;

    public byte[] rcvframe;

    Queue<PcapPacket> queue = new ArrayBlockingQueue<PcapPacket>(20);

    String username;

    private NetworkHandler() {
    }

    public static NetworkHandler getInstance() {
	return networkhandler;
    }

    public void init() {

	List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
							// NICs
	StringBuilder errbuf = new StringBuilder(); // For any error msgs

	int index; // Device Index

	/***************************************************************************
	 * First get a list of devices on this system
	 **************************************************************************/
	int r = Pcap.findAllDevs(alldevs, errbuf);
	if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
	    System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
	    return;
	}

	/*****************************************
	 * Show all network interfaces
	 *****************************************/

	int i = 0;
	for (PcapIf device : alldevs) {
	    String description = (device.getDescription() != null) ? device.getDescription()
		    : "No description available";
	    System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
	}

	/*****************************************
	 * Select network interfaces
	 *****************************************/
	Scanner scanner = new Scanner(System.in);
	while (true) {
	    try {
		System.out.print("Which [number] of Network-Adapter to use: ");
		index = Integer.parseInt(scanner.next());
		if (index >= 0 && index < i) {
		    break;
		} else {
		    System.out.println("Incorrect, retry...");
		    continue;
		}
	    } catch (NumberFormatException e) {
		System.out.println("Incorrect, retry...");
		continue;
	    }
	}

	PcapIf device = alldevs.get(index); // We know we have atleast 1 device

	System.out.printf("\nChoosing '%s' on your behalf:\n",
		(device.getDescription() != null) ? device.getDescription() : device.getName());

	// Username Request

	Scanner sc = new Scanner(System.in);
	while (true) {

	    System.out.print("Please insert username: ");
	    username = sc.nextLine();

	    if (username.length() != 0) {
		break;
	    }

	}

	// Initialize Network-Interface

	int snaplen = 64 * 1024; // Capture all packets, no trucation
	int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
	int timeout = 10 * 1000; // 10 seconds in millis
	pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
	try {
	    src_mac = device.getHardwareAddress();
	} catch (IOException e) {
	    System.out.println("Can't get Source-MAC!");
	    e.printStackTrace();
	}

    }

    public void sendFrame(byte[] frame) {

	// create Ethernet Header
	frame = ArrayConverter.concatenate(dst_mac, src_mac, frametype, frame);

	// Send EAPOL-Frame
	if (pcap.sendPacket(frame) != Pcap.OK) {
	    System.err.println(pcap.getErr());
	}
    }

    public byte[] receiveFrame() {

	// Initialize PacketHandler for listening

	PcapPacketHandler<Queue<PcapPacket>> handler = new PcapPacketHandler<Queue<PcapPacket>>() {

	    public void nextPacket(PcapPacket packet, Queue<PcapPacket> queue) {

		// Byte-Array for Frames
		rcvframe = packet.getByteArray(0, packet.size());

		// PcapPacket permanent = new PcapPacket(packet);

		// IF EAPOL Request Frame?
		if ((rcvframe[12] == -120) && (rcvframe[13] == -114)
			&& (rcvframe[18] == 1 || rcvframe[18] == 3 || rcvframe[18] == 4)) {
		    // Put in Queue
		    // queue.offer(permanent);
		    // Leave the Loop
		    pcap.breakloop();
		}
	    }
	};

	pcap.loop(100, handler, queue);

	return rcvframe;
    }

    public void closeCon() {

	pcap.close();

    }

}
