/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tlsserver;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import javax.net.ssl.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@ru.de>
 */
public class TLSServer extends Thread {

    private static final Logger LOGGER = LogManager.getLogger(TLSServer.class);

    private static final String PATH_TO_JKS = "eckey192.jks";

    private static final String JKS_PASSWORD = "password";

    private static final String PROTOCOL = "TLS";

    private static final int PORT = 55443;

    private String[] cipherSuites = null;

    private final int port;

    private final SSLContext sslContext;

    private ServerSocket serverSocket;

    private boolean shutdown;

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
	sslContext.init(keyManagers, trustManagers, null);

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
	LOGGER.info("SSL Server successfully initialized!");
    }

    public static KeyStore readKeyStore(String keystorePath, String password) throws KeyStoreException, IOException,
	    NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException {
	KeyStore keyStore = KeyStore.getInstance("JKS");
	FileInputStream fis = null;
	try {
	    fis = new FileInputStream(keystorePath);
	    keyStore.load(fis, password.toCharArray());
	} finally {
	    if (fis != null) {
		fis.close();
	    }
	}
	return keyStore;
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
		} catch (Exception ex) {
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

	    }
	    LOGGER.info("|| shutdown complete");
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
    }

    public void shutdown() {
	this.shutdown = true;
	LOGGER.info("shutdown signal received");
    }

    public static void main(String[] args) throws Exception {

	if (args.length == 5 && args[4].equalsIgnoreCase("BC")) {
	    Security.removeProvider("SunPKCS11-NSS");
	    Security.removeProvider("SunEC");
	    Security.insertProviderAt(new BouncyCastleProvider(), 1);
	    System.out.println("Using BC provider");
	}
	for (Provider p : Security.getProviders()) {
	    System.out.println(p);
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
	    System.out.println("Usage (run with): java -jar [name].jar [jks-path] "
		    + "[password] [protocol] [port] \n (set [protocol] to TLS)");
	    return;
	}

	KeyStore keyStore = readKeyStore(path, password);
	TLSServer server = new TLSServer(keyStore, password, protocol, port);
	Thread t = new Thread(server);
	t.start();
    }

    public String[] getCipherSuites() {
	return cipherSuites;
    }
}
