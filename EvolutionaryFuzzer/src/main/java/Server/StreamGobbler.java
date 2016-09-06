/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Server;

/**
 * An asymetric Streamreader, which reads a Stream, and marks when the output of
 * the Stream equals reaches a specific state. This Class is used to see if an
 * Implementation is already in a state, where it is able to see if the
 * implementation is ready to accept incoming connections
 *
 * @author Robert Merget - robert.merget@rub.de
 */
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

class StreamGobbler extends Thread {
    private static final Logger LOG = Logger.getLogger(StreamGobbler.class.getName());

    private InputStream is;
    private String type;
    private OutputStream os;
    private volatile boolean hasAccepted = false;
    private String accepted;

    StreamGobbler(InputStream is, String type, String accepted) {
	this(is, type, null, accepted);

    }

    StreamGobbler(InputStream is, String type, OutputStream redirect, String accepted) {
	this.is = is;
	this.type = type;
	this.os = redirect;
	this.accepted = accepted;
    }

    @Override
    public void run() {
	try {
	    PrintWriter pw = null;
	    if (os != null) {
		pw = new PrintWriter(os);
	    }

	    InputStreamReader isr = new InputStreamReader(is);
	    BufferedReader br = new BufferedReader(isr);
	    String line = null;
	    while ((line = br.readLine()) != null) {
		if (pw != null) {
		    pw.println(line);
		}
		if (line.contains(accepted)) {
		    hasAccepted = true;
		} else {

		}
		LOG.log(Level.FINEST, line);
	    }
	    if (pw != null) {
		pw.flush();
	    }
	} catch (IOException ioe) {

	}
    }

    public void close() {
	try {
	    os.close();
	} catch (IOException ex) {
	    Logger.getLogger(StreamGobbler.class.getName()).log(Level.SEVERE, null, ex);
	}
	try {
	    is.close();
	} catch (IOException ex) {
	    Logger.getLogger(StreamGobbler.class.getName()).log(Level.SEVERE, null, ex);
	}
    }

    /**
     * Returns if the Streamreader has seen the Specified "accepted" String yet
     * 
     * @return If the Streamreader has seen the Specified "accepted" String yet
     */
    public boolean accepted() {
	return hasAccepted;
    }
}
