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
 * EAP-TLS Factory create EAP and EAP-TLS Frames
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class EapTlsFactory extends EapFactory {

    @Override
    protected EAPFrame createFrame(String element, int id) {
	switch (element) {
	    case "STARTEAP":
		return new Start8021X((byte) 0x01);
	    case "EAPID":
		return new Identity(new Eap8021X((byte) 0x01), NetworkHandler.getInstance().username, id);
	    case "EAPNAK":
		return new Nak(new Eap8021X((byte) 0x01), id);
	    case "EAPTLSFRAGACK":
		return new FragAck(new Eap8021X((byte) 0x01), id);
	}

	return null;
    }

    @Override
    protected EAPFrame createFrame(String element, int id, byte[] tlspacket) {
	switch (element) {
	    case "EAPTLSCH":
		return new ClientHello(new Eap8021X((byte) 0x01), id, tlspacket);
	    case "EAPTLSFRAGSTART":
		return new FragStart(new Eap8021X((byte) 0x01), id, tlspacket);
	    case "EAPTLSFRAG":
		return new Frag(new Eap8021X((byte) 0x01), id, tlspacket);
	    case "EAPTLSFRAGEND":
		return new FragEnd(new Eap8021X((byte) 0x01), id, tlspacket);
	}

	return null;

    }

}
