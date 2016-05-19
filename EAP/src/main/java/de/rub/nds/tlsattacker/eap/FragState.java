/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.eap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * State for the Fragmentation process. Sends the EAP-ACKs. Change state if a
 * Frag or Fragend Frame was received.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class FragState implements EapState {

    private static final Logger LOGGER = LogManager.getLogger(FragState.class);

    EapolMachine eapolMachine;

    int id, count;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    SplitTLS fragment = SplitTLS.getInstance();

    EAPFrame eapstart;

    byte[] data = {};

    public FragState(EapolMachine eapolMachine, int id) {

	this.eapolMachine = eapolMachine;
	this.id = id;

    }

    public FragState(EapolMachine eapolMachine, int id, int count) {

	this.eapolMachine = eapolMachine;
	this.id = id;
	this.count = count;

    }

    @Override
    public void send() {
	// TODO Auto-generated method stub

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

	if (count == 0) {
	    eapstart = eaptlsfactory.createFrame("EAPTLSFRAGSTART", id, tlspacket);
	} else {
	    eapstart = eaptlsfactory.createFrame("EAPTLSFRAG", id, tlspacket);
	}

	LOGGER.debug("sendTLS(): {}", eapolMachine.getState());

	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public byte[] receive() {
	data = nic.receiveFrame();
	id = (int) data[19]; // Get ID

	LOGGER.debug("receive() TLS-FLAG: {}", Byte.toString(data[23]));

	if (data[23] == (byte) 0x00 && count < (fragment.getCountPacket() - 2)) {
	    count++;
	    eapolMachine.setState(new FragState(eapolMachine, id, count));
	} else {
	    eapolMachine.setState(new FragEndState(eapolMachine, id));
	}

	LOGGER.debug("change State to: {}", eapolMachine.getState());

	return data;
    }

    @Override
    public String getState() {
	return "FragState";
    }

    @Override
    public int getID() {

	return id;

    }

}
