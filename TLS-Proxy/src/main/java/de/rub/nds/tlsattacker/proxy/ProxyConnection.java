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
import de.rub.nds.tlsattacker.core.config.ConfigIO;
import de.rub.nds.tlsattacker.core.socket.TlsAttackerSslSocket;
import java.io.FileInputStream;
import java.io.IOException;
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

    public ProxyConnection(ProxyConfig proxyConfig, Socket socket) throws IOException {
        this.incomingSocket = socket;
        this.proxyConfig = proxyConfig;
        if (proxyConfig.getDefaultConfig() != null) {
            try (FileInputStream fis = new FileInputStream(proxyConfig.getDefaultConfig())) {
                config = ConfigIO.read(fis);
            }
        } else {
            config = Config.createConfig();
        }
        System.out.println("Accepted a connection!");
    }

    @Override
    public void run() {
        while (!incomingSocket.isClosed()) {
            try {
                if (incomingSocket.getInputStream().available() > 0) {
                    if (!initialized) {

                        System.out.println("Received data");
                        InputStream inputStream = incomingSocket.getInputStream();
                        if (inputStream.read() != 5) {
                            throw new Exception("Connection is not Socks5 - only socks5 supported");
                        }
                        int length = inputStream.read();
                        System.out.println("Read:" + length);
                        for (int i = 0; i < length; i++) {
                            System.out.println("Reading authentication method");
                            inputStream.read();
                        }
                        System.out.println("Sending answer");
                        incomingSocket.getOutputStream().write(new byte[] {0x05, 0x00});
                        incomingSocket.getOutputStream().flush();
                        String line = "";
                        LOGGER.info("Received: " + line);
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
            } catch (Exception E) {
            }
        }
    }

    public void setSocket(TlsAttackerSslSocket socket) {
        this.socket = socket;
    }
}
