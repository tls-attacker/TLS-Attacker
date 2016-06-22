/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class Main {

    /**
     *
     * @param args
     */
    public static void main(String args[]) {
        //TODO write a console interface
        Controller controller = new FuzzerController();
        controller.startFuzzer();
    }
    private static final Logger LOG = Logger.getLogger(Main.class.getName());
}
