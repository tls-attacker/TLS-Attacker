/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tracetool.main;

import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class Main {

    // Loosely based on sysexits.h
    public static final int EX_OK = 0;
    public static final int EX_GENERAL = 1;
    public static final int EX_USAGE = 64;
    public static final int EX_CONFIG = 78;

    public static void main(String... args) {
        try {
            (new TraceTool(args)).run();
        } catch (ParameterException pe) {
            System.exit(EX_USAGE);
        } catch (ConfigurationException ce) {
            System.exit(EX_CONFIG);
        } catch (Exception e) {
            System.out.println("Encountered an unknown exception. See debug for more info.");
            System.out.println(e);
            System.exit(EX_GENERAL);
        }
        System.exit(EX_OK);
    }
}