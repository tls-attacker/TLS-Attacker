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
 * Throws Success Message, if EAP-Frame Success was received.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class SuccessState implements EapState {

    private static final Logger LOGGER = LogManager.getLogger(FailureState.class);

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    public SuccessState(EapolMachine eapolMachine, int id) {

        this.eapolMachine = eapolMachine;
        this.id = id;

        nic.closeCon();
        LOGGER.info("Success, Connection permit!");
        // System.exit(0);

    }

    @Override
    public void send() {

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

    }

    @Override
    public byte[] receive() {
        return null;
    }

    @Override
    public String getState() {
        return "SuccessState";
    }

    @Override
    public int getID() {

        return 0;

    }

}
