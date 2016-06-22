/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import java.util.ArrayList;

/**
 * The Server Manager keeps Track of the different TLS Server Processes. The
 * Executor can ask the ServerManager for a free Server, and the ServerManager
 * returns a currently unused Server. This Asymmetric Design was chosen to
 * support TLS Implementation with longer Bootup Times. Just add more Servers to
 * the ServerManager than you got Threads in the ThreadPool.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerManager
{

    private ArrayList<TLSServer> serverList;

    /**
     * Singleton
     *
     * @return Instance of the ServerManager
     */
    public static ServerManager getInstance()
    {
        return ServerManagerHolder.INSTANCE;
    }

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
        //System.out.println("Getting Server");
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
                //Try to get a free Server

                server.occupie();
                //System.out.println("Got:"+server.toString());
                return server;
            }
            i++;
            if (startSearch < System.currentTimeMillis() - 60000)
            {
                //Searched longer than a minute and didnt find a free Server
                throw new RuntimeException("Could not find a free Server, if you have >= #servers than #executors there is a bug in the Code that causes Servers to not be properly released or not restart properly.");
            }
        }
    }

    /**
     * Removes all Server from the ServerList. This method is mostly Implemented
     * for UnitTesting purposes.
     */
    public void clear()
    {
        serverList = new ArrayList<>();
    }

    //Singleton

    private static class ServerManagerHolder
    {

        private static final ServerManager INSTANCE = new ServerManager();
    }
}
