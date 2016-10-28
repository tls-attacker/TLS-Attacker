/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.server;

import tlsattacker.fuzzer.server.ServerSerializer;
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;
import tlsattacker.fuzzer.helper.GitIgnoreFileFilter;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages the different Servers that the fuzzer is configured with.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerManager {

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

    private ServerManager() {
	serverList = new ArrayList<>();
    }

    /**
     * Adds a TLSServer to the List of TLSServers
     * 
     * @param server Server to add
     */
    public void addServer(TLSServer server) {
	serverList.add(server);
    }

    /**
     * Reads the config files and adds Servers to the serverList accordingly
     * @param config Config file used to find the correct config folder
     */
    public void init(FuzzerGeneralConfig config) {
	File file = new File(config.getServerCommandFromFile());
	if (!file.exists()) {
	    LOG.log(Level.INFO, "Could not find Server Configuration Files:{0}", file.getAbsolutePath());
	    LOG.log(Level.INFO, "You can create new Configuration files with the command new-server");
	    System.exit(-1);

	} else {
	    if (file.isDirectory()) {
		File[] filesInDic = file.listFiles(new GitIgnoreFileFilter());
		if (filesInDic.length == 0) {
		    LOG.log(Level.INFO, "No Server Configurations Files in the Server Config Folder:{0}",
			    file.getAbsolutePath());
		    LOG.log(Level.INFO, "You can create new Configuration files with the command new-server");
		    System.exit(-1);
		} else {
		    // ServerConfig is a Folder
		    for (File f : filesInDic) {
			try {
			    if (f.isFile()) {
				TLSServer server = ServerSerializer.read(f);
				addServer(server);
			    }
			} catch (Exception ex) {
			    LOG.log(Level.SEVERE, "Could not read Server!", ex);
			}
		    }
		}
	    } else {
		LOG.log(Level.INFO, "Could not find Server Configuration Files:{0}", file.getAbsolutePath());
		LOG.log(Level.INFO, "You can create new Configuration files with the command new-server");
		System.exit(-1);
	    }
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
	    if (startSearch < System.currentTimeMillis() - 60000) {
		// Searched longer than a minute and didnt find a free Server
		throw new RuntimeException(
			"Could not find a free Server, if you have >= #servers than #executors there is a bug in the Code that causes Servers to not be properly released or not restart properly.");
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
     * @return
     */
    public int getServerCount() {
	return serverList.size();
    }

    /**
     * Returns the number of currently free servers
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
    
    private static final Logger LOG = Logger.getLogger(ServerManager.class.getName());
}