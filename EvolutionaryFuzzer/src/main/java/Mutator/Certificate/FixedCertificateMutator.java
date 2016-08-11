/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Mutator.Certificate;

import TestVector.ServerCertificateKeypair;
import Config.ConfigManager;
import Config.EvolutionaryFuzzerConfig;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FixedCertificateMutator extends CertificateMutator {

    private List<X509CertificateObject> clientCertList;
    private List<ServerCertificateKeypair> serverPairList;
    private Random r;

    public FixedCertificateMutator() {
	try {
	    // TODO Config
	    this.clientCertList = new ArrayList<>();
	    this.serverPairList = new ArrayList<>();
	    EvolutionaryFuzzerConfig fc = ConfigManager.getInstance().getConfig();
	    if (fc.getKeystore() == null) {
		fc.setKeystore("../resources/rsa1024.jks");
	    }
	    if (fc.getPassword() == null) {
		fc.setPassword("password");
	    }
	    if (fc.getAlias() == null || fc.getAlias().equals("")) {
		fc.setAlias("alias");
	    }
	    KeyStore ks = KeystoreHandler.loadKeyStore(fc.getKeystore(), fc.getPassword());

	    java.security.cert.Certificate sunCert = ks.getCertificate(fc.getAlias());
	    if (sunCert == null) {
		throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
			+ "certificate alias and key? (Current alias: " + "alias" + ")");
	    }
	    byte[] certBytes = sunCert.getEncoded();

	    ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
	    org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);

	    org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[1];
	    certs[0] = cert;
	    org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs);

	    X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));
	    r = new Random();
	    clientCertList.add(x509CertObject);
	    serverPairList.add(new ServerCertificateKeypair(new File(fc.getOutputFolder()
		    + "certificates/server/key.pem"), new File(fc.getOutputFolder() + "certificates/server/cert.pem")));
	} catch (KeyStoreException ex) {
	    Logger.getLogger(FixedCertificateMutator.class.getName()).log(Level.SEVERE, null, ex);
	} catch (IOException ex) {
	    Logger.getLogger(FixedCertificateMutator.class.getName()).log(Level.SEVERE, null, ex);
	} catch (NoSuchAlgorithmException ex) {
	    Logger.getLogger(FixedCertificateMutator.class.getName()).log(Level.SEVERE, null, ex);
	} catch (CertificateException ex) {
	    Logger.getLogger(FixedCertificateMutator.class.getName()).log(Level.SEVERE, null, ex);
	}
    }

    @Override
    public X509CertificateObject getClientCertificate() {
	return clientCertList.get(r.nextInt(clientCertList.size()));
    }

    @Override
    public ServerCertificateKeypair getServerCertificateKeypair() {
	return serverPairList.get(r.nextInt(serverPairList.size()));
    }

}
