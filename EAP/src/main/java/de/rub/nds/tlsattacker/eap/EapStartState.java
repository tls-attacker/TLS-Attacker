/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.eap;

/**
 * Set EAP-TLS Statemachine in Start-State and send EAP-Start out. Change the
 * State if a Identity Frame was received.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class EapStartState implements EapState {

    EapolMachine eapolMachine;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    byte[] data = {};

    public EapStartState(EapolMachine eapolMachine) {

	this.eapolMachine = eapolMachine;
    }

    @Override
    public void send() {

	EAPFrame eapstart = eaptlsfactory.createFrame("STARTEAP", 0);
	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

    }

    @Override
    public byte[] receive() {

	data = nic.receiveFrame();
	int id = (int) data[19]; // Get ID

	// Identity Frame?
	if (data[22] == 0x01) {
	    eapolMachine.setState(new IdentityState(eapolMachine, id));
	} else {
	    eapolMachine.setState(new EapStartState(eapolMachine));

	}

	return data;
    }

    @Override
    public String getState() {
	return "EapStartState";
    }

    @Override
    public int getID() {

	return (int) data[19];

    }

}
