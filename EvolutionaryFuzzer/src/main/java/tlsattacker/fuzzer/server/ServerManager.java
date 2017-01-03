/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.server;

import tlsattacker.fuzzer.config.FuzzerGeneralConfig;
import tlsattacker.fuzzer.helper.GitIgnoreFileFilter;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import tlsattacker.fuzzer.exceptions.FuzzerConfigurationException;

/**
 * Manages the different Servers that the fuzzer is configured with.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerManager {

    private static final Logger LOGGER = LogManager.getLogger(ServerManager.class);

    /**
     * Singleton
     * 
     * @return Instance of the ServerManager
     */
    public static ServerManager getInstance() {
        return ServerManagerHolder.INSTANCE;
    }

    /**
     * The List of servers that the Manager keeps track of
     */
    private ArrayList<TLSServer> serverList;

    /**
     * General Config used
     */
    private FuzzerGeneralConfig config;

    private ServerManager() {
        serverList = new ArrayList<>();
    }

    public FuzzerGeneralConfig getConfig() {
        return config;
    }

    /**
     * Adds a TLSServer to the List of TLSServers
     * 
     * @param server
     *            Server to add
     */
    public void addServer(TLSServer server) {
        serverList.add(server);
    }

    /**
     * Reads the config files and adds Servers to the serverList accordingly
     * 
     * @param config
     *            Config file used to find the correct config folder
     * @throws tlsattacker.fuzzer.exceptions.FuzzerConfigurationException
     */
    public void init(FuzzerGeneralConfig config) throws FuzzerConfigurationException {
        this.config = config;
        File file = new File(config.getServerCommandFromFile());
        if (!file.exists()) {
            LOGGER.info("Could not find Server Configuration Files:{0}", file.getAbsolutePath());
            LOGGER.info("You can create new Configuration files with the command new-server");
            throw new FuzzerConfigurationException("Server not properly configured!");

        } else {
            if (file.isDirectory()) {
                File[] filesInDic = file.listFiles(new GitIgnoreFileFilter());
                if (filesInDic.length == 0) {
                    LOGGER.info("No Server Configurations Files in the Server Config Folder:{0}",
                            file.getAbsolutePath());
                    LOGGER.info("You can create new Configuration files with the command new-server");
                    throw new FuzzerConfigurationException("Server not properly configured!");
                } else {
                    // ServerConfig is a Folder
                    for (File f : filesInDic) {
                        try {
                            if (f.isFile()) {
                                TLSServer server = ServerSerializer.read(f);
                                addServer(server);
                            }
                        } catch (Exception ex) {
                            LOGGER.error(ex.getLocalizedMessage(), ex);
                        }
                    }
                }
            } else {
                LOGGER.info("Could not find Server Configuration Files:{0}", file.getAbsolutePath());
                LOGGER.info("You can create new Configuration files with the command new-server");
                throw new FuzzerConfigurationException("Server not properly configured!");
            }
        }
        for (TLSServer server : serverList) {
            server.setConfig(config);
        }

    }

    /**
     * Trys to get an unused Server from the ServerList. Starts over if there is
     * no free Server available. If it still searches for a free Server after 10
     * seconds, it throws an Exception. If a server is found, the Server is
     * reserved. Its the caller duty to release the Server once it is finished.
     * 
     * @return A Free Server
     */
    public synchronized TLSServer getFreeServer() {
        long startSearch = System.currentTimeMillis();
        if (serverList.isEmpty()) {
            throw new ConfigurationException("No Servers configured!");
        }
        int i = 0;
        while (true) {
            TLSServer server = serverList.get(i % serverList.size());
            if (server.isFree()) {
                // Try to get a free Server

                server.occupie();
                return server;
            }
            i++;
            if (startSearch < System.currentTimeMillis() - config.getBootTimeout() + 1000) {
                // Searched longer than a minute and didnt find a free Server
                throw new RuntimeException(
                        "Could not find a free Server, if you have >= #servers than #executors there is a bug in the Code that causes Servers to not be properly released or not restart properly.");
            }
        }
    }

    /**
     * Waits till all TLSServers are free and occupies them all and returns
     * them.
     * 
     * @return List of all configured Servers
     */
    public synchronized List<TLSServer> occupieAllServers() {
        long startSearch = System.currentTimeMillis();
        if (serverList.isEmpty()) {
            throw new ConfigurationException("No Servers configured!");
        }
        int i = 0;
        while (true) {
            boolean goOn = true;
            for (TLSServer server : serverList) {
                if (!server.isFree()) {
                    goOn = false;
                }
            }
            if (goOn) {
                for (TLSServer server : serverList) {
                    server.occupie();
                }
                return serverList;
            }
            // Not all servers were free
            i++;
            if (startSearch < System.currentTimeMillis() - config.getBootTimeout() + 1000) {
                // Searched longer than a minute and didnt find a free Server
                throw new RuntimeException("Could not get all Configured Servers as free");
            }
        }
    }

    /**
     * Removes all Server from the ServerList. This method is mostly implemented
     * for UnitTesting purposes.
     */
    public void clear() {
        serverList = new ArrayList<>();
    }

    /**
     * Returns the Number of Servers the Fuzzer controls
     * 
     * @return Number of Servers the Fuzzer controls
     */
    public int getNumberOfServers() {
        return serverList.size();
    }

    /**
     * Returns the number of Servers in the serverList
     * 
     * @return
     */
    public int getServerCount() {
        return serverList.size();
    }

    /**
     * Returns the number of currently free servers
     * 
     * @return
     */
    public int getFreeServerCount() {
        int count = 0;
        for (TLSServer server : serverList) {
            if (server.isFree()) {
                count++;
            }
        }
        return serverList.size();
    }

    /**
     * Returns all Servers
     * 
     * @return
     */
    public List<TLSServer> getAllServers() {
        return Collections.unmodifiableList(serverList);
    }

    /**
     * Singleton
     */
    private static class ServerManagerHolder {

        /**
         * Singleton
         */
        private static final ServerManager INSTANCE = new ServerManager();

        private ServerManagerHolder() {
        }
    }
}
