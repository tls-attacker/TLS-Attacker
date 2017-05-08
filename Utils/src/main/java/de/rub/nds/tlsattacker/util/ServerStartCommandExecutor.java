/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class ServerStartCommandExecutor {

    private static final Logger LOGGER = LogManager.getLogger(ServerStartCommandExecutor.class);
    static final int MAX_OUTPUT_LINES = 1000;

    /**
     * Command.
     */
    private final String startCommand;

    /**
     * Process to start the server
     */
    Process process;

    List<String> serverOutput;

    List<String> serverErrorOutput;

    /**
     * Instance of this executor.
     * 
     * @param command
     *            The command to be executed.
     */
    public ServerStartCommandExecutor(final String command) {
        this.startCommand = command + " ";
        serverOutput = new LinkedList<>();
        serverErrorOutput = new LinkedList<>();
    }

    /**
     * This function starts the server using the startCommand
     * 
     * @throws java.io.IOException
     */
    public void startServer() throws IOException {
        Runtime rt = Runtime.getRuntime();
        process = rt.exec(startCommand);
        // error fetcher
        CommandLineFetcher error = new CommandLineFetcher(process.getErrorStream(), serverErrorOutput);

        // output fetcher
        CommandLineFetcher output = new CommandLineFetcher(process.getInputStream(), serverOutput);

        error.start();
        output.start();

        LOGGER.info("Server successfully started.");
    }

    public List<String> getServerOutput() {
        return Collections.unmodifiableList(serverOutput);
    }

    public List<String> getServerErrorOutput() {
        return Collections.unmodifiableList(serverErrorOutput);
    }

    private String getOutputString(List<String> list) {
        StringBuilder sb = new StringBuilder();
        for (String s : list) {
            sb.append(s).append(System.getProperty("line.separator"));
        }
        return sb.toString();
    }

    public String getServerOutputString() {
        return getOutputString(serverOutput);
    }

    public String getServerErrorOutputString() {
        return getOutputString(serverErrorOutput);
    }

    public void clearServerOutput() {
        serverOutput.clear();
    }

    public void clearServerErrorOutput() {
        serverErrorOutput.clear();
    }

    /**
     * Checks whether server is still running
     * 
     * @return
     */
    public boolean isServerTerminated() {
        try {
            process.exitValue();
        } catch (IllegalThreadStateException itse) {
            return false;
        }
        return true;
    }

    /**
     * Kills the server subprocess using the process destroy function.
     */
    public void terminateServer() {
        process.destroy();
    }

    private class CommandLineFetcher extends Thread {

        /**
         * Input stream from the command line.
         */
        private final InputStream is;

        /**
         * Exception found during processing.
         */
        Exception e;

        /**
         *
         */
        List<String> output;

        /**
         * Constructor
         * 
         * @param is
         *            command line input stream
         */
        CommandLineFetcher(InputStream is, List<String> out) {
            this.is = is;
            this.output = out;
        }

        @Override
        public void run() {
            try {
                InputStreamReader isr = new InputStreamReader(is);
                BufferedReader br = new BufferedReader(isr);
                String line;
                while ((line = br.readLine()) != null) {
                    LOGGER.debug(line);
                    output.add(line);
                    if (output.size() > MAX_OUTPUT_LINES) {
                        output.remove(0);
                    }
                }
                is.close();
            } catch (IOException ioe) {
                e = ioe;
            }
        }
    }

}
