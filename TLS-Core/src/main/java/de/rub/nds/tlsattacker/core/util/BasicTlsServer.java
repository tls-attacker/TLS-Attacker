/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.BadRandom;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BasicTlsServer extends Thread {

    private static final Logger LOGGER = LogManager.getLogger();

    private String[] cipherSuites = null;
    private final int port;
    private final SSLContext sslContext;
    private ServerSocket serverSocket;
    private boolean shutdown;
    boolean closed = true;

    /**
     * Very dirty but ok for testing purposes
     */
    private volatile boolean initialized;

    public BasicTlsServer(KeyStore keyStore, String password, String protocol, int port) throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException,
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
            LOGGER.debug("Supported cipher suites ("
                    + sslContext.getServerSocketFactory().getSupportedCipherSuites().length + ")");
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
                    if (socket != null) {
                        ConnectionHandler ch = new ConnectionHandler(socket);
                        Thread t = new Thread(ch);
                        t.start();
                    }

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

    private void preSetup() throws SocketException, IOException {
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        serverSocket = serverSocketFactory.createServerSocket(port);
        serverSocket.setReuseAddress(true);
        // TODO:
        // if (cipherSuites != null) {
        // ((SSLServerSocket)
        // serverSocket).setEnabledCipherSuites(cipherSuites);
        // }
        LOGGER.debug("Presetup successful");
        initialized = true;
    }

    public void shutdown() {
        this.shutdown = true;
        LOGGER.debug("Shutdown signal received");
        try {
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException ex) {
            LOGGER.error(ex);
        }
    }

    public String[] getCipherSuites() {
        return cipherSuites;
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
