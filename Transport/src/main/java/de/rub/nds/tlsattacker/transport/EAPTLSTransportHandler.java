/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import de.rub.nds.tlsattacker.eap.EapolMachine;
import de.rub.nds.tlsattacker.eap.ExtractTLS;
import de.rub.nds.tlsattacker.eap.FragState;
import de.rub.nds.tlsattacker.eap.NetworkHandler;
import de.rub.nds.tlsattacker.eap.SplitTLS;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author root
 */
class EAPTLSTransportHandler implements TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger(EAPTLSTransportHandler.class);

    NetworkHandler nic = NetworkHandler.getInstance();

    EapolMachine eapolMachine = new EapolMachine();

    ExtractTLS extractor = new ExtractTLS();

    byte[] test;

    byte[] tlsraw;

    int y = 0, countpackets = 0;

    @Override
    public void initialize(String address, int port) throws IOException {
	nic.init();

	while (true) {

	    LOGGER.debug("initialize() send Frame: {}", eapolMachine.getState());
	    eapolMachine.send();
	    LOGGER.debug("initialize() receive Frame: {}", eapolMachine.getState());
	    test = eapolMachine.receive();
	    if (test[22] == 0x0d && test[23] == 0x20) {
		break;
	    }
	}
    }

    @Override
    public void sendData(byte[] data) throws IOException {

	SplitTLS fragment = SplitTLS.getInstance();
	countpackets = 0;
	y = 0;
	tlsraw = new byte[0];

	/*
	 * // Test suche nach Certificate Verify in data for (int i = 0; i <
	 * data.length; i++) { // Suchen nach der Certificate Verify Nachricht
	 * im Vektor if (data[i] == (byte) 0x0f && data[i + 1] == (byte) 0x00 &&
	 * data[i + 2] == (byte) 0x00 && data[i + 3] == (byte) 0x29) { data[i +
	 * 4] = (byte) 0xff; data[i + 5] = (byte) 0xff; } }
	 */
	if (data.length > 1024) {
	    eapolMachine.setState(new FragState(eapolMachine, eapolMachine.getID(), 0));
	    fragment.split(data);
	    countpackets = fragment.getCountPacket();
	    LOGGER.debug("sendData() SplitTLS packets: {}", Integer.toString(countpackets));
	}

	while (true) {

	    LOGGER.debug("sendData() send TLS-Frame: {}", eapolMachine.getState());
	    LOGGER.debug("sendData() send Fragment: {}", y);
	    LOGGER.debug("Content tlsraw: {}", ArrayConverter.bytesToHexString(tlsraw));

	    if ("HelloState".equals(eapolMachine.getState())) {
		eapolMachine.sendTLS(data);

		// Empfängt gleich das erste Server-Paket nach dem das letzte
		// Client-Paket versendet worden ist
		LOGGER.debug("sendData() receive TLS-Frame: {}", eapolMachine.getState());

		test = eapolMachine.receive();
		LOGGER.debug("received content: {}", ArrayConverter.bytesToHexString(test));
		// und fügt es dem tlsraw Container hinzu
		tlsraw = ArrayConverter.concatenate(tlsraw, extractor.extract(test));

	    } else

	    if (("FragState".equals(eapolMachine.getState()) || "HelloState".equals(eapolMachine.getState()))
		    && countpackets != 0) {
		eapolMachine.sendTLS(fragment.getFragment(y));
		y++;

		// Empfängt gleich das erste Server-Paket nach dem das letzte
		// Client-Paket versendet worden ist
		LOGGER.debug("sendData() receive TLS-Frame: {}", eapolMachine.getState());

		test = eapolMachine.receive();
		LOGGER.debug("received content: {}", ArrayConverter.bytesToHexString(test));
		// und fügt es dem tlsraw Container hinzu
		tlsraw = ArrayConverter.concatenate(tlsraw, extractor.extract(test));

	    } else if ("FragStartState".equals(eapolMachine.getState())) {
		eapolMachine.send();

		// Empfängt gleich das erste Server-Paket nach dem das letzte
		// Client-Paket versendet worden ist
		LOGGER.debug("sendData() receive TLS-Frame: {}", eapolMachine.getState());

		test = eapolMachine.receive();
		LOGGER.debug("received content: {}", ArrayConverter.bytesToHexString(test));
		// und fügt es dem tlsraw Container hinzu
		tlsraw = ArrayConverter.concatenate(tlsraw, extractor.extract(test));

	    } else if ("FragEndState".equals(eapolMachine.getState()) && countpackets != 0 && (countpackets - y != 0)) {
		eapolMachine.sendTLS(fragment.getFragment(y));
		y++;

		// Empfängt gleich das erste Server-Paket nach dem das letzte
		// Client-Paket versendet worden ist
		LOGGER.debug("sendData() receive TLS-Frame: {}", eapolMachine.getState());

		test = eapolMachine.receive();
		// und fügt es dem tlsraw Container hinzu
		tlsraw = ArrayConverter.concatenate(tlsraw, extractor.extract(test));

	    } else if ("NoFragState".equals(eapolMachine.getState())) {
		eapolMachine.sendTLS(data);
		LOGGER.debug("sendData() receive TLS-Frame: {}", eapolMachine.getState());
		test = eapolMachine.receive();
		break;

	    } else if ("FinishedState".equals(eapolMachine.getState())) {
		eapolMachine.sendTLS(data);
		LOGGER.debug("sendData() receive TLS-Frame: {}", eapolMachine.getState());
		test = eapolMachine.receive();
		break;

	    } else {
		eapolMachine.sendTLS(data);

	    }

	    LOGGER.debug("Fragments: {}", Integer.toString(y));

	    if (countpackets == y && !("FragStartState".equals(eapolMachine.getState()))) {
		LOGGER.debug("All Fragments sent: {}", Integer.toString(countpackets));
		LOGGER.debug("Content tlsraw: {}", ArrayConverter.bytesToHexString(tlsraw));
		break;
	    }

	}
    }

    @Override
    public byte[] fetchData() throws IOException {

	int i;
	boolean loop = true;
	byte[] finished = new byte[0];

	if ("FinishedState".equals(eapolMachine.getState())) {
	    LOGGER.debug("fetchData() send Frame: {}", eapolMachine.getState());
	    eapolMachine.send();

	    for (i = 0; i < tlsraw.length; i++) {
		// Suchen nach der CCS Nachricht im Vektor
		if (tlsraw[i] == (byte) 0x14 && tlsraw[i + 1] == (byte) 0x03 && tlsraw[i + 2] == (byte) 0x03
			&& tlsraw[i + 3] == (byte) 0x00 && tlsraw[i + 4] == (byte) 0x01 && tlsraw[i + 5] == (byte) 0x01) {
		    finished = new byte[tlsraw.length - i];
		    break;
		}
	    }

	    System.arraycopy(tlsraw, i, finished, 0, tlsraw.length - i);
	    LOGGER.debug("Content tlsraw: {}", ArrayConverter.bytesToHexString(finished));

	    loop = false;
	    return finished;
	}

	while (loop == true) {

	    // Code wird nur ausgeführt wenn Server Hello fragmentiert ist
	    if (countpackets != 0) {
		LOGGER.debug("fetchData() send Frame: {}", eapolMachine.getState());
		eapolMachine.send();

		LOGGER.debug("fetchData() receive Frame: {}", eapolMachine.getState());
		test = eapolMachine.receive();

		tlsraw = ArrayConverter.concatenate(tlsraw, extractor.extract(test));
	    }

	    if (test[23] != (byte) 0xc0) {
		LOGGER.debug("fetchData() send Frame or lastfragment: {}", eapolMachine.getState());
		eapolMachine.send();
		break;
	    }

	}
	LOGGER.debug("Content tlsraw: {}", ArrayConverter.bytesToHexString(tlsraw));
	return tlsraw;

    }

    @Override
    public void closeConnection() {
	nic.closeCon();
    }
}
