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

public class EapolMachine {

    EapState eapStartState;

    EapState state;

    public EapolMachine() {

	eapStartState = new EapStartState(this);
	state = eapStartState;

    }

    public void send() {
	state.send();
    }

    public void sendTLS(byte[] tlspacket) {
	state.sendTLS(tlspacket);
    }

    public byte[] receive() {
	return state.receive();
    }

    public void setState(EapState state) {
	this.state = state;
    }

    public String getState() {
	return state.getState();
    }

    public int getID() {
	return state.getID();
    }

}
