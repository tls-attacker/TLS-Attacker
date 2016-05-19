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
 * Interface for EAP-TLS Statemachine.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public interface EapState {

    public void send();

    public void sendTLS(byte[] tlspacket);

    public byte[] receive();

    public String getState();

    public int getID();

}
