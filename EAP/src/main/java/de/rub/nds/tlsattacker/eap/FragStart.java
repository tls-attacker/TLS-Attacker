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
 * Construct the EAP Start Frame with first TLS-Packet and EAP-FLag 0xc0.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class FragStart extends EAPResponseDecorator {

    private EAPFrame eapframe;

    private byte[] tlspacket;

    public FragStart(EAPFrame eapframe, int id, byte[] tlspacket) {
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

        frame = new byte[12];
        eaplength = (short) ((frame.length - 2) + tlspacket.length);
        tlslength = fragment.getSizeInt();

        frame[0] = (byte) (super.eaplength >>> 8); // Length
        frame[1] = (byte) (super.eaplength); // Length
        frame[2] = 0x02; // Code
        frame[3] = (byte) id; // ID
        frame[4] = (byte) (super.eaplength >>> 8); // Length
        frame[5] = (byte) (super.eaplength); // Length
        frame[6] = 0x0d; // Type
        frame[7] = (byte) 0xc0; // EAP-Flag Start Fragment
        frame[8] = (byte) (super.tlslength >>> 24); // TLS-Length
        frame[9] = (byte) (super.tlslength >>> 16); // TLS-Length
        frame[10] = (byte) (super.tlslength >>> 8); // TLS-Length
        frame[11] = (byte) (super.tlslength); // TLS-Length
    }

}
