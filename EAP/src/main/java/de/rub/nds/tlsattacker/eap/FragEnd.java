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

/**
 * Construct the EAP Frag End Frame with last TLS-Packet and EAP-FLag 0x00.
 * http://tools.ietf.org/html/rfc3748
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class FragEnd extends EAPResponseDecorator {

    EAPFrame eapframe;

    byte[] tlspacket;

    public FragEnd(EAPFrame eapframe, int id, byte[] tlspacket) {
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

	SplitTLS fragment = SplitTLS.getInstance();

	frame = new byte[8];
	eaplength = (short) ((frame.length - 2) + tlspacket.length);
	tlslength = fragment.getSizeInt();

	frame[0] = (byte) (super.eaplength >>> 8); // Length
	frame[1] = (byte) (super.eaplength); // Length
	frame[2] = 0x02; // Code
	frame[3] = (byte) id; // ID
	frame[4] = (byte) (super.eaplength >>> 8); // Length
	frame[5] = (byte) (super.eaplength); // Length
	frame[6] = 0x0d; // Type
	frame[7] = (byte) 0x00; // EAP-Flag

    }

}
