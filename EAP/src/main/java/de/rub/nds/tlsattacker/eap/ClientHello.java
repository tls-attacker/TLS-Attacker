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
 * Construct the EAP-TLS Response Frame for ClientHello or other Frames with
 * EAP-TLS Flag 0x80 (Length include, not fragmented)
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
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
