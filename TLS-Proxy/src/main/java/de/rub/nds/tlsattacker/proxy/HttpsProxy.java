/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.proxy;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.cert.CertificateException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpsProxy {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProxyConfig proxyConfig;

    public HttpsProxy(ProxyConfig config) {
        this.proxyConfig = config;
    }

    public void start() throws IOException {
        LOGGER.info("Proxy started...");
        ServerSocketFactory ssf = getServerSocketFactory();
        ServerSocket serverSocket = new ServerSocket(proxyConfig.getListeningPort());
        while (true) {
            try {
                Socket socket = serverSocket.accept();
                LOGGER.info("Received a connection");
                ProxyConnection proxyConnection = new ProxyConnection(proxyConfig, socket);
                Thread t = new Thread(proxyConnection);
                t.start();
            } catch (IOException ex) {
                LOGGER.error("Caught an IO exception...", ex);
            }
        }
    }

    private ServerSocketFactory getServerSocketFactory() {
        SSLServerSocketFactory ssf = null;
        try {
            SSLContext ctx = createContext();

            ssf = ctx.getServerSocketFactory();
            return ssf;
        } catch (Exception E) {
            LOGGER.error("Could not create ServerSocketFactory", E);
            throw new RuntimeException(E);
        }
    }

    public SSLContext createContext()
            throws KeyStoreException,
                    NoSuchAlgorithmException,
                    FileNotFoundException,
                    IOException,
                    CertificateException,
                    UnrecoverableKeyException,
                    KeyManagementException,
                    java.security.cert.CertificateException {
        SSLContext context = SSLContext.getInstance("TLS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] passphrase = proxyConfig.getPassword().toCharArray();

        try (FileInputStream fis = new FileInputStream(proxyConfig.getServerCertificate())) {
            keyStore.load(fis, passphrase);
        }
        keyManagerFactory.init(keyStore, passphrase);

        // We trust all clients - do not copy this code if you find it on github
        context.init(
                keyManagerFactory.getKeyManagers(),
                new TrustManager[] {
                    new X509ExtendedTrustManager() {
                        @Override
                        public void checkClientTrusted(
                                X509Certificate[] xcs, String string, Socket socket)
                                throws java.security.cert.CertificateException {}

                        @Override
                        public void checkServerTrusted(
                                X509Certificate[] xcs, String string, Socket socket)
                                throws java.security.cert.CertificateException {}

                        @Override
                        public void checkClientTrusted(
                                X509Certificate[] xcs, String string, SSLEngine ssle)
                                throws java.security.cert.CertificateException {}

                        @Override
                        public void checkServerTrusted(
                                X509Certificate[] xcs, String string, SSLEngine ssle)
                                throws java.security.cert.CertificateException {}

                        @Override
                        public void checkClientTrusted(X509Certificate[] xcs, String string)
                                throws java.security.cert.CertificateException {}

                        @Override
                        public void checkServerTrusted(X509Certificate[] xcs, String string)
                                throws java.security.cert.CertificateException {}

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
                },
                null);
        return context;
    }
}
