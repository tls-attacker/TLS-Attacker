package de.rub.nds.tlsattacker.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class KeystoreHandler {

    public static KeyStore loadKeyStore(final String keyStorePath, final String keyStorePassword)
	    throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
	KeyStore ks = KeyStore.getInstance("JKS");
	ks.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());

	return ks;
    }
}
