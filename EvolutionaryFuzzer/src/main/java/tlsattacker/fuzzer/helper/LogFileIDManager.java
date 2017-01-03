/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.helper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Small Helper to Generate incrementing IDs used to generate unique Filenames
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class LogFileIDManager {

    private static final Logger LOGGER = LogManager.getLogger(LogFileIDManager.class);

    /**
     * Singleton: Return the Instance of the LogFileIDManager
     * 
     * @return Instance of the LogFileIDManager
     */
    public static LogFileIDManager getInstance() {
        return LogFileIDManagerHolder.INSTANCE;
    }

    /**
     * A counter to generate Filenames
     */
    private int id = 0;

    /**
     * A counter which assures unique names even threw application resets
     */
    private int run = 0;

    /**
     * Private Constructor since its a Singleton
     */
    private LogFileIDManager() {
        FileWriter w = null;
        try {
            File f = new File("file.id");
            if (f.exists()) {
                BufferedReader r = new BufferedReader(new FileReader(f));
                String s = r.readLine();
                run = Integer.parseInt(s);
                run++;
                f.delete();
            }
            f.createNewFile();
            w = new FileWriter(f);
            w.write("" + run);
        } catch (IOException ex) {
            LOGGER.error(ex.getLocalizedMessage(), ex);
        } finally {
            try {
                w.close();
            } catch (IOException ex) {
                LOGGER.error(ex.getLocalizedMessage(), ex);
            }
        }

    }

    /**
     * Generates a new UniqueID
     * 
     * @return Unique ID
     */
    public synchronized int getID() {
        id++;
        return id;
    }

    /**
     * Returns a random Filename
     * 
     * @return Random Filename
     */
    public synchronized String getFilename() {
        id++;
        return "" + run + "." + id;
    }

    /**
     * Singleton
     */
    private static class LogFileIDManagerHolder {

        /**
         * Singleton
         */
        private static final LogFileIDManager INSTANCE = new LogFileIDManager();

        private LogFileIDManagerHolder() {
        }
    }

}
