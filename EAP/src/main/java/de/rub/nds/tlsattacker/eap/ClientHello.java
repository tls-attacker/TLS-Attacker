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

import de.rub.nds.tlsattacker.util.ArrayConverter;

public class ClientHello extends EAPResponseDecorator {

    EAPFrame eapframe;

    byte[] tlspacket;

    public ClientHello(EAPFrame eapframe, int id, byte[] tlspacket) {
	this.eapframe = eapframe;
	this.id = id;
	this.tlspacket = tlspacket;
	createFrame();

    }

    @Override
    public byte[] getFrame() {

	return ArrayConverter.concatenate(eapframe.getFrame(), frame, tlspacket);
    }

    @Override
    public void createFrame() {

	frame = new byte[12];
	tlslength = tlspacket.length;
	eaplength = (short) ((frame.length - 2) + tlslength);

	frame[0] = (byte) (super.eaplength >>> 8); // Length
	frame[1] = (byte) (super.eaplength); // Length
	frame[2] = 0x02; // Code
	frame[3] = (byte) id; // ID muss aus dem ConnectionHandler kommen //ID
	frame[4] = (byte) (super.eaplength >>> 8); // Length
	frame[5] = (byte) (super.eaplength); // Length
	frame[6] = 0x0d; // Type EAP-TLS
	frame[7] = (byte) 0x80; // EAP-Flag
	frame[8] = (byte) (super.tlslength >>> 24); // TLS_Length
	frame[9] = (byte) (super.tlslength >>> 16);
	frame[10] = (byte) (super.tlslength >>> 8);
	frame[11] = (byte) (super.tlslength);

    }

}
