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
 * EAP-Factory to create EAP and EAP-TLS Frames
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public abstract class EapFactory {

    public EAPFrame getFrame(String typ, int id) {

	EAPFrame frame = createFrame(typ, id);

	return frame;
    }

    protected abstract EAPFrame createFrame(String element, int id);

    protected abstract EAPFrame createFrame(String element, int id, byte[] tlspacket);

}
