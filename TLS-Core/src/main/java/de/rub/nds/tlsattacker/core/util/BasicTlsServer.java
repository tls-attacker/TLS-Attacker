/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import javax.net.ssl.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BasicTlsServer extends Thread {

    private static final Logger LOGGER = LogManager.getLogger();

    private String[] cipherSuites = null;
    private final int port;
    private final SSLContext sslContext;
    private SSLServerSocket serverSocket;
    private boolean shutdown;
    boolean closed = true;

    /** Very dirty but ok for testing purposes */
    private volatile boolean initialized;

    public BasicTlsServer(KeyStore keyStore, String password, String protocol, int port)
            throws KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    CertificateException,
                    UnrecoverableKeyException,
                    KeyManagementException {

        this.port = port;

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, password.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, trustManagers, new BadRandom());

        cipherSuites = sslContext.getServerSocketFactory().getSupportedCipherSuites();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Provider: " + sslContext.getProvider());
            LOGGER.debug(
                    "Supported cipher suites ("
                            + sslContext.getServerSocketFactory().getSupportedCipherSuites().length
                            + ")");
            for (String c : sslContext.getServerSocketFactory().getSupportedCipherSuites()) {
                LOGGER.debug(" " + c);
            }
        }
    }

    @Override
    public void run() {
        try {
            preSetup();
            closed = false;
            while (!shutdown) {
                try {
                    LOGGER.info("Listening on port " + port + "...\n");
                    final Socket socket = serverSocket.accept();
                    ConnectionHandler ch = new ConnectionHandler(socket);
                    Thread t = new Thread(ch);
                    t.start();
                } catch (IOException ex) {
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
            closed = true;
        } catch (IOException ex) {
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        } finally {
            try {
                if (serverSocket != null && !serverSocket.isClosed()) {
                    serverSocket.close();
                    serverSocket = null;
                }
            } catch (IOException e) {
                LOGGER.debug(e);
            }
            LOGGER.info("Shutdown complete");
        }
    }

    private void preSetup() throws IOException {
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);
        serverSocket.setReuseAddress(true);
        // TODO:
        // if (cipherSuites != null) {
        // ((SSLServerSocket)
        // serverSocket).setEnabledCipherSuites(cipherSuites);
        // }
        LOGGER.debug("Pre-setup successful");
        initialized = true;
    }

    public void shutdown() {
        this.shutdown = true;
        LOGGER.debug("Shutdown signal received");
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException ex) {
            LOGGER.error(ex);
        }
    }

    public String[] getCipherSuites() {
        return cipherSuites;
    }

    public Set<ProtocolVersion> getEnabledProtocolVersions() {
        return Arrays.stream(serverSocket.getEnabledProtocols())
                .map(
                        versionString -> {
                            switch (versionString) {
                                case "SSLv2":
                                    return ProtocolVersion.SSL2;
                                case "SSLv3":
                                    return ProtocolVersion.SSL3;
                                case "TLSv1":
                                    return ProtocolVersion.TLS10;
                                case "TLSv1.1":
                                    return ProtocolVersion.TLS11;
                                case "TLSv1.2":
                                    return ProtocolVersion.TLS12;
                                case "TLSv1.3":
                                    return ProtocolVersion.TLS13;
                                default:
                                    return null;
                            }
                        })
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    public boolean isInitialized() {
        return initialized;
    }

    public int getPort() {
        if (serverSocket != null) {
            return serverSocket.getLocalPort();
        } else {
            return port;
        }
    }
}
