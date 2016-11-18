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
 * Construct the 802.1x Header for encapsulated EAP
 * https://standards.ieee.org/findstds/standard/802.1X-2010.html
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class Eap8021X extends EAPFrame {

    byte version;

    public Eap8021X(byte version) {

        this.version = version;
        createFrame();

    }

    @Override
    public final void createFrame() {

        frame = new byte[2];
        frame[0] = version;
        frame[1] = 0x00;

    }

}
