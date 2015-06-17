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

public class Identity extends EAPResponseDecorator {
    EAPFrame eapframe;

    byte[] userbyte;

    String username;

    public Identity(EAPFrame eapframe, String username, int id) {
	this.eapframe = eapframe;
	this.username = username;
	this.id = id;
	createFrame();
    }

    @Override
    public byte[] getFrame() {
	// TODO Auto-generated method stub
	return ArrayConverter.concatenate(eapframe.getFrame(), frame, userbyte);
    }

    @Override
    public void createFrame() {

	this.userbyte = username.getBytes();
	super.eaplength = (short) (5 + userbyte.length); // ( 5 = Code + ID +
							 // Length + Type )

	frame = new byte[7];

	frame[0] = (byte) (super.eaplength >>> 8); // Length
	frame[1] = (byte) (super.eaplength); // Length
	frame[2] = 0x02; // Code:Response
	frame[3] = (byte) id; // ID muss aus dem ConnectionHandler kommen //ID
	frame[4] = (byte) (super.eaplength >>> 8); // Length
	frame[5] = (byte) (super.eaplength); // Length
	frame[6] = 0x01; // Type:Identity

	// TODO Auto-generated method stub

    }

}
