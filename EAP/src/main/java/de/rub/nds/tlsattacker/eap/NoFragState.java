/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Felix Lange
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
package de.rub.nds.tlsattacker.eap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NoFragState implements EapState {

    private static final Logger LOGGER = LogManager.getLogger(NoFragState.class);

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    byte[] data = {};

    public NoFragState(EapolMachine eapolMachine, int id) {

	this.eapolMachine = eapolMachine;
	this.id = id;

    }

    @Override
    public void send() {
	// TODO Auto-generated method stub

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

	LOGGER.debug("receive() TLS-FLAG: {}", Byte.toString(data[23]));

	if (data[23] == (byte) 0x80) {
	    eapolMachine.setState(new NoFragState(eapolMachine, id));
	} else if (data[18] == 0x04) {
	    eapolMachine.setState(new FailureState(eapolMachine, id));
	} else {
	    eapolMachine.setState(new FragState(eapolMachine, id));
	}

	LOGGER.debug("change State to: {}", eapolMachine.getState());
	return data;
    }

    @Override
    public String getState() {
	return "NoFragState";
    }

    @Override
    public int getID() {

	return id;

    }

}
