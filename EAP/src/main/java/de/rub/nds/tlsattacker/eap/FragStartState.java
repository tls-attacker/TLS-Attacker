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
 * State for the start of a Fragmentation. Change state if a Frag or Fragend
 * Frame was received.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class FragStartState implements EapState {

    private EapolMachine eapolMachine;

    private int id;

    private EapFactory eaptlsfactory = new EapTlsFactory();

    private NetworkHandler nic = NetworkHandler.getInstance();

    private EAPFrame eapstart;

    private byte[] data = {};

    public FragStartState(EapolMachine eapolMachine, int id) {

        this.eapolMachine = eapolMachine;
        this.id = id;

    }

    @Override
    public void send() {

        eapstart = eaptlsfactory.createFrame("EAPTLSFRAGACK", id);
        nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

        eapstart = eaptlsfactory.createFrame("EAPTLSFRAG", id, tlspacket);
        nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public byte[] receive() {
        data = nic.receiveFrame();
        id = data[19]; // Get ID

        if (data[23] == (byte) 0xc0 || data[23] == (byte) 0x40) {
            eapolMachine.setState(new FragStartState(eapolMachine, id));
        } else if (data[23] == (byte) 0x00) {
            eapolMachine.setState(new FragEndState(eapolMachine, id));
        } else {
            eapolMachine.setState(new FragState(eapolMachine, id, 1));
        }
        return data;
    }

    @Override
    public String getState() {
        return "FragStartState";
    }

    @Override
    public int getID() {

        return id;

    }

}
