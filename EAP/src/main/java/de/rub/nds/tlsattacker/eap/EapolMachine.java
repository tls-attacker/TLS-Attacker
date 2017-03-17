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
 * EAPol Machine for send/receive Frames, set/get States and get ID from
 * Protocolflow
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class EapolMachine {

    private EapState eapStartState;

    private EapState state;

    public EapolMachine() {

        eapStartState = new EapStartState(this);
        state = eapStartState;

    }

    public void send() {
        state.send();
    }

    public void sendTLS(byte[] tlspacket) {
        state.sendTLS(tlspacket);
    }

    public byte[] receive() {
        return state.receive();
    }

    public void setState(EapState state) {
        this.state = state;
    }

    public String getState() {
        return state.getState();
    }

    public int getID() {
        return state.getID();
    }

}
