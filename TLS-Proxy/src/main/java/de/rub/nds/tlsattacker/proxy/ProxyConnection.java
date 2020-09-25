/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.proxy;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.ConfigIO;
import de.rub.nds.tlsattacker.core.socket.TlsAttackerSslSocket;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ProxyConnection implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();

    private Socket incomingSocket;

    private TlsAttackerSslSocket outgoingSocket;

    private State state;
    private boolean initialized = false;
    private Config config;
    private ProxyConfig proxyConfig;

    public ProxyConnection(ProxyConfig proxyConfig, Socket socket) throws FileNotFoundException {
        this.incomingSocket = socket;
        this.proxyConfig = proxyConfig;
        if (proxyConfig.getDefaultConfig() != null) {
            config = ConfigIO.read(new FileInputStream(proxyConfig.getDefaultConfig()));
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
                        incomingSocket.getOutputStream().write(new byte[] { 0x05, 0x00 });
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
                                outgoingSocket = new TlsAttackerSslSocket(config, hostname, port, config
                                        .getDefaultClientConnection().getTimeout());
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
        ;
    }
}
