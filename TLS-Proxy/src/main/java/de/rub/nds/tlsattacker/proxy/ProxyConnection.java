/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.proxy;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.socket.TlsAttackerSslSocket;
import java.io.InputStream;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProxyConnection implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Socket incomingSocket;

    private TlsAttackerSslSocket socket;

    private final boolean initialized = false;
    private final Config config;
    private final ProxyConfig proxyConfig;

    public ProxyConnection(ProxyConfig proxyConfig, Config config, Socket socket) {
        this.incomingSocket = socket;
        this.proxyConfig = proxyConfig;
        this.config = config;
    }

    public ProxyConfig getProxyConfig() {
        return proxyConfig;
    }

    @Override
    public void run() {
        while (!incomingSocket.isClosed()) {
            try {
                if (incomingSocket.getInputStream().available() > 0) {
                    if (!initialized) {

                        InputStream inputStream = incomingSocket.getInputStream();
                        if (inputStream.read() != 5) {
                            throw new Exception("Connection is not Socks5 - only socks5 supported");
                        }
                        int length = inputStream.read();
                        for (int i = 0; i < length; i++) {
                            LOGGER.debug("Reading authentication method");
                            inputStream.read();
                        }
                        incomingSocket.getOutputStream().write(new byte[] {0x05, 0x00});
                        incomingSocket.getOutputStream().flush();
                        String line = "";
                        LOGGER.info("Received: {}", line);
                        String[] parsed = line.split(" ");
                        if (parsed.length >= 3) {
                            String method = parsed[0];
                            String destinationhostport = parsed[1];
                            String protocol = parsed[2];

                            if (method.equals("CONNECT")) {
                                String hostname = destinationhostport.split(":")[0];
                                int port = Integer.parseInt(destinationhostport.split(":")[1]);
                                socket =
                                        new TlsAttackerSslSocket(
                                                config,
                                                hostname,
                                                port,
                                                config.getDefaultClientConnection().getTimeout());
                            } else {
                                // ???
                            }
                        }
                    }
                } else {
                    Thread.currentThread().sleep(50);
                }
            } catch (Exception e) {
                LOGGER.debug("Error in proxy connection loop", e);
            }
        }
    }

    public void setSocket(TlsAttackerSslSocket socket) {
        this.socket = socket;
    }
}
