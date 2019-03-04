/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.nonblocking;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class AcceptorCallableTest {

    private Thread t;

    private AcceptorCallable callable;

    private ServerSocket socket;

    private FutureTask<Socket> task;

    @Before
    public void setUp() throws IOException {
        socket = new ServerSocket(0);
        callable = new AcceptorCallable(socket);
        task = new FutureTask<>(callable);
        t = new Thread(task);
    }

    @After
    public void shutDown() throws IOException {
        socket.close();
    }
}
