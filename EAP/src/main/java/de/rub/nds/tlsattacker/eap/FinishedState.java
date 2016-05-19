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
 * Last state in the protocolflow, sends the last EAP-ACK and switch to Success
 * or Failure. This depends on the received frame.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class FinishedState implements EapState {

    private static final Logger LOGGER = LogManager.getLogger(FragEndState.class);

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    byte[] data = {};

    public FinishedState(EapolMachine eapolMachine, int id) {

	this.eapolMachine = eapolMachine;
	this.id = id;

    }

    @Override
    public void send() {

	EAPFrame eapstart = eaptlsfactory.createFrame("EAPTLSFRAGACK", id);

	LOGGER.debug("send(): {}", eapolMachine.getState());

	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

	EAPFrame eapstart = eaptlsfactory.createFrame("EAPTLSCH", id, tlspacket);

	LOGGER.debug("sendTLS(): {}", eapolMachine.getState());

	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public byte[] receive() {

	data = nic.receiveFrame();
	id = (int) data[19]; // Get ID

	if (data[18] == (byte) 0x03) {
	    eapolMachine.setState(new SuccessState(eapolMachine, id));
	} else

	if (data[18] == (byte) 0x04) {
	    eapolMachine.setState(new FailureState(eapolMachine, id));
	}

	return data;
    }

    @Override
    public String getState() {
	return "FinishedState";

    }

    @Override
    public int getID() {

	return id;

    }

}
