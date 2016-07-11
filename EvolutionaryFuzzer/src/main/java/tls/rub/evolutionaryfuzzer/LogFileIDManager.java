/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Small Helper to Generate incrementing IDs used to generate unique Filenames
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class LogFileIDManager {

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
	    Logger.getLogger(LogFileIDManager.class.getName()).log(Level.SEVERE, null, ex);
	} finally {
	    try {
		w.close();
	    } catch (IOException ex) {
		Logger.getLogger(LogFileIDManager.class.getName()).log(Level.SEVERE, null, ex);
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

    public synchronized String getFilename() {
	id++;
	return "" + run + "." + id;
    }

    /**
     * Singleton
     */
    private static class LogFileIDManagerHolder {

	private static final LogFileIDManager INSTANCE = new LogFileIDManager();

	private LogFileIDManagerHolder() {
	}
    }

}
