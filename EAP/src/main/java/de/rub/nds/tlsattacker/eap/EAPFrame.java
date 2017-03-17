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
    protected byte[] frame;

    protected short eaplength;

    protected int tlslength;

    protected int id;

    public byte[] getFrame() {
        return frame;
    }

    public abstract void createFrame();

}
