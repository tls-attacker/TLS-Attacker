/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.eap;

import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * Construct the Identity EAP-Frame with the username.
 * http://tools.ietf.org/html/rfc3748
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
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
