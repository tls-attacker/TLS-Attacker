/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Execute a workflow trace for each new connection/socket that connects to the
 * server.
 *
 * Highly experimental. Just a starting point.
 */
public final class ThreadedServerWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    private ServerSocket serverSocket;
    private Socket socket;
    private final int port;
    private Thread currentThread;
    List<Socket> sockets = new ArrayList<>();
    private final int poolSize = 3;
    private boolean killed = true;
    private boolean shutdown = true;
    private final ExecutorService pool;

    public ThreadedServerWorkflowExecutor(State state) {
        super(WorkflowExecutorType.THREADED_SERVER, state);

        port = config.getDefaultServerConnection().getPort();
        pool = Executors.newFixedThreadPool(poolSize);
        addHook();
    }

    public void addHook() {
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

        synchronized (this) {
            this.currentThread = Thread.currentThread();
        }

        LOGGER.info("Listening on port " + port + "...");
        LOGGER.info("--- use SIGINT to shutdown ---");
        initialize();

        try {
            while (!killed) {
                socket = serverSocket.accept();
                pool.execute(new WorkflowExecutorRunnable(state, socket));
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

    public void initialize() {
        LOGGER.info("Initializing server connection end at port " + port);
        if ((serverSocket != null) && (!serverSocket.isClosed())) {
            LOGGER.debug("Server socket already initialized");
            return;
        }
        try {
            serverSocket = new ServerSocket(port);
            serverSocket.setReuseAddress(true);
        } catch (IOException ex) {
            throw new RuntimeException("Could not instantiate server socket");
        }
        killed = false;
        shutdown = false;
    }

    public void kill() {
        this.killed = true;
    }

    public synchronized void closeSockets() {
        for (Socket s : sockets) {
            LOGGER.debug("Closing socket " + socket);
            try {
                if (s != null) {
                    s.close();
                    s = null;
                } else {
                    LOGGER.debug("... already closed.");
                }
            } catch (IOException ex) {
                LOGGER.debug("Failed to close socket " + socket);
            }
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

    // Straight from the java docs for ExecutorService
    private void shutdownAndAwaitTermination() {
        pool.shutdown(); // Disable new tasks from being submitted
        try {
            // Wait a while for existing tasks to terminate
            if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
                pool.shutdownNow(); // Cancel currently executing tasks
                // Wait a while for tasks to respond to being cancelled
                if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
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
