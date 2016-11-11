/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.eap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * State for No Fragmentation. Change state if a Failure, Finished, Alert, Frag
 * or NoFrag Frame was received.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class NoFragState implements EapState {

    private static final Logger LOGGER = LogManager.getLogger(NoFragState.class);

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    byte[] data = {};

    public NoFragState(EapolMachine eapolMachine, int id) {

        this.eapolMachine = eapolMachine;
        this.id = id;

    }

    @Override
    public void send() {
        // TODO Auto-generated method stub

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

        EAPFrame eapstart = eaptlsfactory.createFrame("EAPTLSCH", id, tlspacket);

        LOGGER.debug("sendTLS(): {}", eapolMachine.getState());

        nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public byte[] receive() {
        data = nic.receiveFrame();
        id = (int) data[19]; // Get ID

        LOGGER.debug("receive() TLS-FLAG: {}", Byte.toString(data[23]));

        if (data[18] == 0x04) {
            eapolMachine.setState(new FailureState(eapolMachine, id));
        } else if (data[28] == (byte) 0x14) {
            // Change Chipher Spec vom Server empfangen?
            LOGGER.debug("receive() TLS Content Type: {}", Byte.toString(data[28]));
            eapolMachine.setState(new FinishedState(eapolMachine, id));

        } else if (data[28] == (byte) 0x15) {
            // Eine AlertMessage vom Server empfangen?
            LOGGER.debug("receive() TLS Content Type: {}", Byte.toString(data[28]));
            eapolMachine.setState(new AlertState(eapolMachine, id));

        } else if (data[23] == (byte) 0x80) {
            eapolMachine.setState(new NoFragState(eapolMachine, id));
        } else {
            eapolMachine.setState(new FragState(eapolMachine, id));
        }

        LOGGER.debug("change State to: {}", eapolMachine.getState());
        return data;
    }

    @Override
    public String getState() {
        return "NoFragState";
    }

    @Override
    public int getID() {

        return id;

    }

}
