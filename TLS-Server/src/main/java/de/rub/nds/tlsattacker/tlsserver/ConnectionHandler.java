/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tlsserver;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class ConnectionHandler implements Runnable {
    /** application socket */
    private final Socket applicationSocket;

    private final static Logger LOGGER = LogManager.getRootLogger();

    /**
     * ConnectionHandler constructor
     * 
     * @param socket
     *            - The socket of the connection
     */
    public ConnectionHandler(final Socket socket) {
	applicationSocket = socket;
    }

    public void run() {

	LOGGER.debug("new Thread started");

	try {
	    final BufferedReader br = new BufferedReader(new InputStreamReader(applicationSocket.getInputStream()));
	    final BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(applicationSocket.getOutputStream()));
	    String line = "";
	    while ((line = br.readLine()) != null) {
		LOGGER.debug(line);
		bw.write("ack");
		bw.flush();
	    }
	} catch (IOException e) {
	    LOGGER.debug(e.getLocalizedMessage(), e);
	} finally {
	    try {
		applicationSocket.close();
	    } catch (final IOException ioe) {
		LOGGER.debug(ioe.getLocalizedMessage(), ioe);
	    }
	}
    }
}
