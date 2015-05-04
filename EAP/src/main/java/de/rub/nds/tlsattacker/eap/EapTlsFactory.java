/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Felix Lange
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
