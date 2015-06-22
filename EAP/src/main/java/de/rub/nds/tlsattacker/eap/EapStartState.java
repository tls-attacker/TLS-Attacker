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
