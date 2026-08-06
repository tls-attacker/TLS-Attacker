/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.task;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveRegexTextAction;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Measures how many TCP connections a refused STARTTLS upgrade costs, using a real listening socket
 * rather than a stubbed transport handler.
 *
 * <p>The scanner runs its tasks with {@code reexecutions = 3}, so without special handling a
 * deterministic refusal is retried until the budget is exhausted, opening a fresh connection each
 * time to be told the same thing again.
 */
public class StarttlsRefusalConnectionCountIT {

    private static final int REEXECUTIONS = 3;

    /** What a server without STARTTLS support answers to the upgrade command. */
    private static final String REFUSAL = "534 Request denied for policy reasons\r\n";

    private ServerSocket serverSocket;
    private Thread acceptThread;
    private final AtomicInteger acceptedConnections = new AtomicInteger();

    @BeforeEach
    public void setUp() throws IOException {
        serverSocket = new ServerSocket(0);
        acceptedConnections.set(0);
        acceptThread =
                new Thread(
                        () -> {
                            while (!serverSocket.isClosed()) {
                                try (Socket socket = serverSocket.accept()) {
                                    acceptedConnections.incrementAndGet();
                                    OutputStream out = socket.getOutputStream();
                                    out.write(REFUSAL.getBytes(StandardCharsets.US_ASCII));
                                    out.flush();
                                } catch (IOException e) {
                                    return;
                                }
                            }
                        });
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    @AfterEach
    public void tearDown() throws IOException, InterruptedException {
        serverSocket.close();
        acceptThread.join(1000);
    }

    /**
     * A refused upgrade must cost exactly one connection. Every additional connection here is one
     * the scanner would open, per target, purely to re-learn an answer that cannot change.
     */
    @Test
    public void testRefusedUpgradeOpensSingleConnection() throws Exception {
        Config config = new Config();
        config.setWorkflowExecutorShouldOpen(true);
        config.setWorkflowExecutorShouldClose(true);
        config.setFinishWithCloseNotify(false);
        config.setStopTraceAfterUnexpected(true);

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^234");
        action.setAbortRegex("^[45]\\d\\d ");
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);

        State state = new State(config, trace);
        state.getTlsContext()
                .setTransportHandler(
                        new ClientTcpTransportHandler(
                                1000, 1000, "localhost", serverSocket.getLocalPort()));

        ParallelExecutor executor = ParallelExecutor.create(1, REEXECUTIONS);
        try {
            executor.bulkExecuteStateTasks(state);
        } finally {
            executor.shutdown();
        }

        System.out.println("ACCEPTED_CONNECTIONS=" + acceptedConnections.get());

        assertEquals(
                1,
                acceptedConnections.get(),
                "A deterministic STARTTLS refusal must not be retried over new connections");
    }
}
