/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Server;

import Server.ServerSerializer;
import Config.EvolutionaryFuzzerConfig;
import Helper.GitIgnoreFileFilter;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerManager
{

    private static final Logger LOG = Logger.getLogger(ServerManager.class.getName());

    /**
     * Singleton
     *
     * @return Instance of the ServerManager
     */
    public static ServerManager getInstance()
    {
        return ServerManagerHolder.INSTANCE;
    }

    private ArrayList<TLSServer> serverList;

    private ServerManager()
    {
        serverList = new ArrayList<>();
    }

    /**
     * Adds a TLSServer to the List of TLSServers
     *
     * @param server
     */
    public void addServer(TLSServer server)
    {
        serverList.add(server);
    }

    public void init(EvolutionaryFuzzerConfig config)
    {
        File file = new File(config.getServerCommandFromFile());
        if (!file.exists())
        {
            LOG.log(Level.INFO, "Could not find Server Configuration Files:" + file.getAbsolutePath());
            LOG.log(Level.INFO, "You can create new Configuration files with the command new-server");
            System.exit(-1);

        }
        else
        {
            if (file.isDirectory())
            {
                File[] filesInDic = file.listFiles(new GitIgnoreFileFilter());
                if (filesInDic.length == 0)
                {
                    LOG.log(Level.INFO, "No Server Configurations Files in the Server Config Folder:"+file.getAbsolutePath());
                    LOG.log(Level.INFO, "You can create new Configuration files with the command new-server");
                    System.exit(-1);
                }
                else
                {
                    // ServerConfig is a Folder
                    for (File f : filesInDic)
                    {
                        try
                        {
                            if (f.isFile())
                            {
                                TLSServer server = ServerSerializer.read(f);
                                addServer(server);
                            }
                        }
                        catch (Exception ex)
                        {
                            LOG.log(Level.SEVERE, "Could not read Server!", ex);
                        }
                    }
                }
            }
            else
            {
                // ServerConfig is a File
                try
                {
                    TLSServer server = ServerSerializer.read(file);
                    addServer(server);

                }
                catch (Exception ex)
                {
                    LOG.log(Level.SEVERE, "Could not read Server!", ex);
                }
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
    public synchronized TLSServer getFreeServer()
    {
        // System.out.println("Getting Server");
        long startSearch = System.currentTimeMillis();
        if (serverList.isEmpty())
        {
            return null;
        }
        int i = 0;
        while (true)
        {
            TLSServer server = serverList.get(i % serverList.size());
            if (server.isFree())
            {
                // Try to get a free Server

                server.occupie();
                // System.out.println("Got:"+server.toString());
                return server;
            }
            i++;
            if (startSearch < System.currentTimeMillis() - Config.ConfigManager.getInstance().getConfig().getTimeout())
            {
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
    public void clear()
    {
        serverList = new ArrayList<>();
    }

    /**
     * Returns the Number of Servers the Fuzzer controls
     *
     * @return Number of Servers the Fuzzer controls
     */
    public int getNumberOfServers()
    {
        return serverList.size();
    }

    public int getServerCount()
    {
        return serverList.size();
    }

    public int getFreeServerCount()
    {
        int count = 0;
        for (TLSServer server : serverList)
        {
            if (server.isFree())
            {
                count++;
            }
        }
        return serverList.size();
    }

    public List<TLSServer> getAllServers()
    {
        return serverList;
    }

    // Singleton
    private static class ServerManagerHolder
    {

        private static final ServerManager INSTANCE = new ServerManager();
    }
}
