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
 * Abstract Class for EAP-Frames
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public abstract class EAPFrame {
    byte[] frame;

    short eaplength;

    int tlslength;

    int id;

    public byte[] getFrame() {
	return frame;
    }

    public abstract void createFrame();

}
