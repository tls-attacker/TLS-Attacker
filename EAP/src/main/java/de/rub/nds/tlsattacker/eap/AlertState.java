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
 * Throws Alert Message, if the alert flag is set in EAP-Frame.
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class AlertState implements EapState {

    private static final Logger LOGGER = LogManager.getLogger(FailureState.class);

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    public AlertState(EapolMachine eapolMachine, int id) {

        this.eapolMachine = eapolMachine;
        this.id = id;

        nic.closeCon();
        LOGGER.info("Alert, Connection refused");
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
        return "AlertState";
    }

    @Override
    public int getID() {

        return 0;

    }

}
