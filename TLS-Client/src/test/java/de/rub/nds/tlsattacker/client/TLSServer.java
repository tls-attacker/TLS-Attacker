/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.client;

import de.rub.nds.modifiablevariable.util.BadRandom;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@ru.de>
 */
public class TLSServer extends Thread {
    // TODO should be in core package
    // TODO should be clean
    private static final Logger LOGGER = LogManager.getLogger("TLSServer");

    private static final String PATH_TO_JKS = "eckey192.jks";

    private static final String JKS_PASSWORD = "password";

    private static final String PROTOCOL = "TLS";

    private static final int PORT = 55443;

    public static KeyStore readKeyStore(String keystorePath, String password) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, password.toCharArray());
        }
        return keyStore;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 5 && args[4].equalsIgnoreCase("BC")) {
            Security.removeProvider("SunPKCS11-NSS");
            Security.removeProvider("SunEC");
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            LOGGER.debug("Using BC provider");
        }
        for (Provider p : Security.getProviders()) {
            LOGGER.debug(p);
        }
        System.setProperty("java.security.debug", "ssl");
        String path;
        String password;
        String protocol;
        int port;

        if (args.length == 4 || args.length == 5) {
            path = args[0];
            password = args[1];
            protocol = args[2];
            port = Integer.parseInt(args[3]);
        } else if (args.length == 0) {
            path = PATH_TO_JKS;
            password = JKS_PASSWORD;
            protocol = PROTOCOL;
            port = PORT;
        } else {
            LOGGER.info("Usage (run with): java -jar [name].jar [jks-path] "
                    + "[password] [protocol] [port] \n (set [protocol] to TLS)");
            return;
        }

        KeyStore keyStore = readKeyStore(path, password);
        TLSServer server = new TLSServer(keyStore, password, protocol, port);
        Thread t = new Thread(server);
        t.start();
    }

    private String[] cipherSuites = null;

    private final int port;

    private final SSLContext sslContext;

    private ServerSocket serverSocket;

    private boolean shutdown;

    /**
     * Very dirty but ok for testing purposes
     */
    private volatile boolean initialized;

    public TLSServer(KeyStore keyStore, String password, String protocol, int port) throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException,
            KeyManagementException {

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

        this.port = port;
        LOGGER.debug("SSL Server successfully initialized!");
    }

    @Override
    public void run() {
        try {
            preSetup();
            while (!shutdown) {
                try {
                    LOGGER.debug("|| waiting for connections...\n");
                    final Socket socket = serverSocket.accept();

                    ConnectionHandler ch = new ConnectionHandler(socket);
                    Thread t = new Thread(ch);
                    t.start();
                } catch (IOException ex) {
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
        } catch (IOException ex) {
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        } finally {
            try {
                if (serverSocket != null) {
                    serverSocket.close();
                    serverSocket = null;
                }
            } catch (IOException e) {
                LOGGER.debug(e);
            }
            LOGGER.debug("|| shutdown complete");
        }
    }

    private void preSetup() throws SocketException, IOException {
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        serverSocket = serverSocketFactory.createServerSocket(port);
        serverSocket.setReuseAddress(true);
        // if (cipherSuites != null) {
        // ((SSLServerSocket)
        // serverSocket).setEnabledCipherSuites(cipherSuites);
        // }
        LOGGER.debug("|| presetup successful");
        initialized = true;
    }

    public void shutdown() {
        this.shutdown = true;
        LOGGER.debug("shutdown signal received");
    }

    public String[] getCipherSuites() {
        return cipherSuites;
    }

    public boolean isInitialized() {
        return initialized;
    }
}
