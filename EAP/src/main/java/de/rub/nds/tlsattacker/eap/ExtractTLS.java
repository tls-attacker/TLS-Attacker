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
 * Extract the TLS Packet from EAP-Frame. It cuts the header information.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class ExtractTLS {

    byte[] frame, tls;

    public ExtractTLS() {

    }

    public byte[] extract(byte[] frame) {
	tls = new byte[frame.length - 28];
	System.arraycopy(frame, 28, tls, 0, frame.length - 28);
	return tls;
    }
}
