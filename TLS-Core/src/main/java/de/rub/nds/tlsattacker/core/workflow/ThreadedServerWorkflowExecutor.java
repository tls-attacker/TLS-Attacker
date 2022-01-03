/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;

/**
 * Execute a workflow trace for each new connection/socket that connects to the server.
 *
 * Highly experimental. Just a starting point.
 */
public class ThreadedServerWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int BACKLOG = 50;
    private static final int POOL_SIZE = 3;

    private ServerSocket serverSocket;
    private final InetAddress bindAddr;
    private final int bindPort;
    private List<Socket> sockets = new ArrayList<>();
    private boolean killed = true;
    private boolean shutdown = true;
    protected final ExecutorService pool;

    public ThreadedServerWorkflowExecutor(State state, ExecutorService pool) {
        super(WorkflowExecutorType.THREADED_SERVER, state);

        bindPort = config.getDefaultServerConnection().getPort();
        String hostname = config.getDefaultServerConnection().getHostname();
        if (hostname != null) {
            InetAddress tempBindAddr;
            try {
                tempBindAddr = InetAddress.getByName(hostname);
            } catch (UnknownHostException e) {
                LOGGER.warn("Failed to resolve bind address {} - Falling back to loopback: {}", hostname, e);
                // we could also fallback to null, which would be any address
                // but I think in the case of an error we might just want to
                // either exit or fallback to a rather closed
                // option, like loopback
                tempBindAddr = InetAddress.getLoopbackAddress();
            }
            bindAddr = tempBindAddr;
            // Java did not allow me to set the bindAddr field in the
            // *single line* try block and the catch block at the same
            // time, because it might already be set...
            // So now we have a temporary variable as a workaround
        } else {
            bindAddr = null;
        }
        this.pool = pool;
        addHook();
    }

    public ThreadedServerWorkflowExecutor(State state) {
        this(state, Executors.newFixedThreadPool(POOL_SIZE));
    }

    private void addHook() {
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                LOGGER.info("Received shutdown signal, shutting down server.");
                kill();
                LOGGER.info("Waiting for connections to be closed...");
                int watchDog = 3;
                while ((!shutdown) && (watchDog > 0)) {
                    try {
                        TimeUnit.SECONDS.sleep(1);
                    } catch (InterruptedException ex) {
                        LOGGER.warn("Problem while waiting, could not sleep");
                    }
                    watchDog--;
                }
                if (!shutdown) {
                    LOGGER.debug("Forcing sockets to close");
                    closeSockets();
                    shutdownAndAwaitTermination();
                }
                LOGGER.debug("Server shutdown complete.");
            }
        });
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        initialize();
        String bindaddrStr = "any";
        if (getBoundAddress() != null) {
            bindaddrStr = getBoundAddress().toString();
        }
        LOGGER.info("Listening on {}:{}...", bindaddrStr, getBoundPort());
        LOGGER.info("--- use SIGINT to shutdown ---");

        try {
            while (!killed) {
                Socket socket = serverSocket.accept();
                this.handleClient(socket);
                sockets.add(socket);
            }
        } catch (IOException ex) {
            if (!killed) {
                throw new RuntimeException("Failed to accept connection");
            }
        } finally {
            closeSockets();
            shutdownAndAwaitTermination();
            shutdown = true;
            LOGGER.info("Server shutdown cleanly");
        }
    }

    protected void handleClient(Socket socket) {
        pool.execute(new WorkflowExecutorRunnable(state, socket, this));
    }

    public void clientDone(Socket socket) {
        if (socket == null) {
            throw new IllegalArgumentException("socket may not be null");
        }
        if (!sockets.contains(socket)) {
            throw new IllegalArgumentException("Unknown socket");
        }
        try {
            if (!socket.isClosed()) {
                socket.close();
            }
            sockets.remove(socket);
        } catch (IOException e) {
            LOGGER.debug("Failed to close socket " + socket);
        }
    }

    private void initialize() {
        LOGGER.info("Initializing server connection end at port " + bindPort);
        if ((serverSocket != null) && (!serverSocket.isClosed())) {
            LOGGER.debug("Server socket already initialized");
            return;
        }
        try {
            serverSocket = new ServerSocket(bindPort, BACKLOG, bindAddr);
            serverSocket.setReuseAddress(true);
        } catch (IOException ex) {
            throw new RuntimeException("Could not instantiate server socket", ex);
        }
        killed = false;
        shutdown = false;
    }

    public void kill() {
        this.killed = true;
        closeSockets();
    }

    private synchronized void closeSockets() {
        for (Socket s : sockets.toArray(new Socket[] {})) {
            LOGGER.debug("Closing socket " + s);
            clientDone(s);
        }

        try {
            LOGGER.debug("Closing server socket ");
            if (serverSocket != null) {
                serverSocket.close();
                serverSocket = null;
            }
        } catch (IOException ex) {
            LOGGER.debug("Failed to close server socket.");
        }
        LOGGER.info("All sockets closed");
    }

    public InetAddress getBoundAddress() {
        return serverSocket.getInetAddress();
    }

    public int getBoundPort() {
        return serverSocket.getLocalPort();
    }

    // Straight from the java docs for ExecutorService
    private void shutdownAndAwaitTermination() {
        pool.shutdown(); // Disable new tasks from being submitted
        try {
            // Wait a while for existing tasks to terminate
            if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
                pool.shutdownNow(); // Cancel currently executing tasks
                // Wait a while for tasks to respond to being cancelled
                if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
                    ;
                }
            }
        } catch (InterruptedException ie) {
            // (Re-)Cancel if current thread also interrupted
            pool.shutdownNow();
            // Preserve interrupt status
            Thread.currentThread().interrupt();
        }
    }
}
