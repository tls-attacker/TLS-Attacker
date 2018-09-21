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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.io.IOException;
import java.net.ConnectException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.security.ssl.SSLSocketImpl;

/**
 * BasicTlsClient for integration tests. A TLS Client thread that establishes a
 * default TLS session with the given TLS server. If no server is specified, try
 * to connect to 127.0.0.1:4433 using TLS1.2 and TLS_RSA_WITH_AES_128_CBC_SHA.
 */
public class BasicTlsClient extends Thread {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CipherSuite cipherSuite;
    private final ProtocolVersion tlsVersion;
    private final String serverHost;
    private final int serverPort;
    private final String serverPrettyName;
    private boolean retryConnect;
    // If retryConnect, sleep retryTimeout milliseconds before retrying
    private int retryTimeout = 100;

    private volatile boolean finished = false;

    public BasicTlsClient(String serverHost, int serverPort, ProtocolVersion version, CipherSuite cipherSuite)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            UnrecoverableKeyException, KeyManagementException {
        this.cipherSuite = cipherSuite;
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.serverPrettyName = serverHost + ":" + serverPort;
        this.tlsVersion = version;
        this.retryConnect = true;
    }

    public BasicTlsClient() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            UnrecoverableKeyException, KeyManagementException {
        this("127.0.0.1", 4433, ProtocolVersion.TLS12, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
    }

    public void setRetryConnect(boolean retryConnect) {
        this.retryConnect = retryConnect;
    }

    @Override
    public void run() {
        SSLSocket socket = null;
        try {
            LOGGER.info("Connecting to " + serverPrettyName);
            if (retryConnect) {
                while (true) {
                    try {
                        socket = getFreshSocket(tlsVersion);
                    } catch (ConnectException x) {
                        LOGGER.info("retry: connect to " + serverPrettyName);
                        TimeUnit.MILLISECONDS.sleep(retryTimeout);
                        continue;
                    }
                    break;
                }
            } else {
                socket = getFreshSocket(tlsVersion);
            }

            socket.getSession().invalidate();
            LOGGER.info("Closing session with " + serverPrettyName);
            socket.close();
            LOGGER.info("Closed (" + serverPrettyName + ")");
        } catch (InterruptedException | IOException ex) {
            LOGGER.error(ex);
        } catch (Exception ex) {
            LOGGER.error(ex);
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                    socket = null;
                }
            } catch (IOException e) {
                LOGGER.debug(e);
            }
            finished = true;
            LOGGER.info("Shutdown complete");
        }
    }

    private SSLSocketImpl getFreshSocket(ProtocolVersion version) throws IOException, Exception {
        SSLContext allowAllContext = getAllowAllContext();
        SSLSocketFactory sslFact = allowAllContext.getSocketFactory();
        SSLSocketImpl socket = (SSLSocketImpl) sslFact.createSocket(serverHost, serverPort);
        socket.setEnabledCipherSuites(new String[] { cipherSuite.name() });

        String versions[] = new String[1];
        switch (version) {
            case SSL3:
                versions[0] = "SSLv3";
                break;
            case TLS10:
                versions[0] = "TLSv1";
                break;
            case TLS11:
                versions[0] = "TLSv1.1";
                break;
            case TLS12:
                versions[0] = "TLSv1.2";
                break;
            default:
                throw new UnsupportedOperationException("This version is not supported");
        }

        socket.setEnabledProtocols(versions);
        return socket;
    }

    protected SSLContext getAllowAllContext() {
        SSLContext allowAllContext = null;
        try {
            allowAllContext = SSLContext.getInstance("TLS");
            allowAllContext.getClientSessionContext().setSessionCacheSize(1);

            // Trust everything
            allowAllContext.init(null, new TrustManager[] { new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] arg0, String arg1)
                        throws CertificateException {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] arg0, String arg1)
                        throws CertificateException {
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            } }, new BadRandom());
        } catch (NoSuchAlgorithmException | KeyManagementException E) {
            LOGGER.warn(E);
        }

        return allowAllContext;
    }

    public boolean isFinished() {
        return finished;
    }
}
