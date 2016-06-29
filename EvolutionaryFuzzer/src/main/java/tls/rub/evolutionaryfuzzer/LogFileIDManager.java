/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import java.util.logging.Logger;

/**
 * Small Helper to Generate incrementing IDs used to generate unique Filenames
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class LogFileIDManager
{
    private static final Logger LOG = Logger.getLogger(LogFileIDManager.class.getName());

    /**
     * Singleton: Return the Instance of the LogFileIDManager
     *
     * @return Instance of the LogFileIDManager
     */
    public static LogFileIDManager getInstance() {
        return LogFileIDManagerHolder.INSTANCE;
    }

    private int id = 0;

    /**
     * Private Constructor since its a Singleton
     */
    private LogFileIDManager()
    {
    }

    /**
     * Generates a new UniqueID
     *
     * @return Unique ID
     */
    public synchronized int getID()
    {
        id++;
        return id;
    }

    /**
     * Singleton
     */
    private static class LogFileIDManagerHolder
    {

        private static final LogFileIDManager INSTANCE = new LogFileIDManager();

        private LogFileIDManagerHolder()
        {
        }
    }

}
