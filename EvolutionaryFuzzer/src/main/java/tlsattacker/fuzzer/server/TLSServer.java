/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.server;

import tlsattacker.fuzzer.exceptions.ServerDoesNotStartException;
import tlsattacker.fuzzer.helper.LogFileIDManager;
import java.io.File;
import java.io.IOException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;

/**
 * This Class represents a single Instance of an Implementation. The
 * Implementation can be started and restarted.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSServer {

    /**
     * Server process
     */
    private Process p = null;

    /**
     * If the Server is currently used for fuzzing
     */
    private boolean free = true;

    /**
     * The IP the Server can be reached on
     */
    private String ip;

    /**
     * The port the Server can be reached on
     */
    private int port;

    /**
     * A unique ID
     */
    private int id = -1;

    /**
     * The command used to start the server
     */
    private String restartServerCommand;

    /**
     * String to wait for to indicate a started server
     */
    private String accepted;

    /**
     * Command that can be used to kill the server
     */
    private String killServerCommand = "";

    /**
     * The ErrorStream reader
     */
    private StreamGobbler errorGobbler;

    /**
     * The OutPutStream reader
     */
    private StreamGobbler outputGobbler;

    /**
     * The ProcessMonitor to monitor for the process end
     */
    private ProcessMonitor procmon = null;
    
    /**
     * FuzzerConfig to use
     */
    private FuzzerGeneralConfig config = null;

    //TODO akward constructor
    public TLSServer() {
        config = null;
        ip = null;
        port = 0;
        restartServerCommand = null;
    }

    /**
     * Creates a new TLSServer. TLSServers should be used in the
     * TLSServerManager
     * 
     * @param config The Config used
     * @param ip
     *            The IP of the Implementation
     * @param port
     *            The Port of the Implementation
     * @param restartServerCommand
     *            The command which should be executed to start the Server
     * @param accepted
     *            The String which the Server prints to the console when the
     *            Server is fully started
     * @param killServerCommand
     */
    public TLSServer(FuzzerGeneralConfig config, String ip, int port, String restartServerCommand, String accepted, String killServerCommand) {
        this.config = config;
        this.ip = ip;
        this.port = port;
        this.restartServerCommand = restartServerCommand;
        this.accepted = accepted;
        this.killServerCommand = killServerCommand;
    }

    public String getKillServerCommand() {
        return killServerCommand;
    }

    public void setKillServerCommand(String killServerCommand) {
        this.killServerCommand = killServerCommand;
    }

    public String getAccepted() {
        return accepted;
    }

    public String getRestartServerCommand() {
        return restartServerCommand;
    }

    /**
     * Returns the IP of the Server
     * 
     * @return IP of the Server
     */
    public String getIp() {
        return ip;
    }

    /**
     * Returns the Port of the Server
     * 
     * @return Port of the Server
     */
    public int getPort() {
        return port;
    }

    /**
     * 
     * @param ip
     */
    public void setIp(String ip) {
        this.ip = ip;
    }

    /**
     * 
     * @param port
     */
    public void setPort(int port) {
        this.port = port;
    }

    public void setRestartServerCommand(String restartServerCommand) {
        this.restartServerCommand = restartServerCommand;
    }

    public void setAccepted(String accepted) {
        this.accepted = accepted;
    }

    /**
     * Marks this Server. A Marked Server is currently used by the Fuzzer. A
     * Server should not be marked twice.
     */
    public synchronized void occupie() {
        if (this.free == false) {
            throw new IllegalStateException("Trying to occupie an already occupied Server");
        }
        this.free = false;
    }

    /**
     * Returns True if the Server is currently free to use
     * 
     * @return True if the Server is currently free to use
     */
    public synchronized boolean isFree() {
        return free;
    }

    /**
     * Releases an occupied Server, so that it can be used further for other
     * Testvectors
     */
    public synchronized void release() {
        if (this.free == true) {
            throw new IllegalStateException("Trying to release an already released Server");
        }
        this.free = true;
    }

    /**
     * Starts the Server by executing the restart Server command
     * 
     * @param keyFile
     */
    public synchronized void start(String prefix, File certificateFile, File keyFile) {

        // You have to ooccupie a Server to start it
        if (!this.isFree()) {
            if (p != null) {
                stop();
            }
            restart(prefix, certificateFile, keyFile);
        } else {
            throw new IllegalStateException("Cant start a not marked Server. Occupie it first!");
        }
    }

    /**
     * Restarts the Server by executing the restart Server command
     * 
     * @param keyFile
     */
    public synchronized void restart(String prefix, File certificateFile, File keyFile) {
        if (!this.isFree()) {
            if (p != null) {
                stop();
            }
            try {
                if (config.isRandomPort()) {
                    Random r = new Random();
                    port = 1024 + r.nextInt(4096);

                }
                id = LogFileIDManager.getInstance().getID();
                String command = (prefix + restartServerCommand).replace("[id]", "" + id);
                command = command.replace("[output]", config.getTracesFolder()
                        .getAbsolutePath());
                command = command.replace("[port]", "" + port);
                command = command.replace("[cert]", "" + certificateFile.getAbsolutePath());
                command = command.replace("[key]", "" + keyFile.getAbsolutePath());
                LOG.log(Level.FINE, "Starting Server:{0}", command);
                long time = System.currentTimeMillis();
                Runtime rt = Runtime.getRuntime();
                p = rt.exec(command);

                // any error message?
                errorGobbler = new StreamGobbler(p.getErrorStream(), "ERR", accepted);
                errorGobbler.setName("Error Gobbler - " + id);
                // any output?
                outputGobbler = new StreamGobbler(p.getInputStream(), "OUT", accepted);
                outputGobbler.setName("Output Gobbler - " + id);
                // kick them off
                errorGobbler.start();
                outputGobbler.start();
                procmon = ProcessMonitor.create(p);
                while (!outputGobbler.accepted()) {

                    try {
                        Thread.sleep(50);
                    } catch (InterruptedException ex) {
                        Logger.getLogger(TLSServer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    if (System.currentTimeMillis() - time >= config.getBootTimeout()) {
                        throw new ServerDoesNotStartException("Timeout in StreamGobler, Server never finished starting");
                    }
                }
            } catch (IOException t) {
                t.printStackTrace();
            }

        } else {
            throw new IllegalStateException("Cant restart a not marked Server. Occupie it first!");
        }

    }

    /**
     * Checks if the server has booted
     * 
     * @return True if the server has booted
     */
    public synchronized boolean serverHasBooted() {
        return outputGobbler != null && outputGobbler.accepted() && p != null;
    }

    /**
     * Returns True if the Process the Server started has exited
     * 
     * @return True if the Process the Server started has exited
     */
    public synchronized boolean exited() {
        if (procmon == null) {
            throw new IllegalStateException("Server not yet Started!");
        } else {
            return procmon.isComplete();
        }

    }

    /**
     * Returns the ID assigned to the currently started Server, the ID changes
     * after every restart
     * 
     * @return
     * @returnID assigned to the currently started Server
     */
    public synchronized int getID() {
        return id;
    }

    @Override
    public String toString() {
        return "TLSServer{free=" + free + ", ip=" + ip + ", port=" + port + ", id=" + id + ", restartServerCommand="
                + restartServerCommand + ", accepted=" + accepted + '}';
    }

    /**
     * Stops the Server process
     */
    public void stop() {
        try {
            LOG.log(Level.FINE, "Stopping Server");
            if (p != null) {
                p.destroy();
                p.waitFor();
                if (config.isUseKill()) {
                    Runtime rt = Runtime.getRuntime();
                    p = rt.exec(killServerCommand);
                    p.waitFor();
                }
            }
        } catch (IOException | InterruptedException E) {
            E.printStackTrace();
        }
    }

    public FuzzerGeneralConfig getConfig() {
        return config;
    }

    public void setConfig(FuzzerGeneralConfig config) {
        this.config = config;
    }
    
    private static final Logger LOG = Logger.getLogger(TLSServer.class.getName());
}
