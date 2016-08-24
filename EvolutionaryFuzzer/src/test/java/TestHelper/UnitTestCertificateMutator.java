/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package TestHelper;

import Certificate.ClientCertificateStructure;
import Config.ConfigManager;
import Config.EvolutionaryFuzzerConfig;
import Mutator.Certificate.CertificateMutator;
import Mutator.Certificate.FixedCertificateMutator;
import Certificate.ServerCertificateStructure;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * This mutator does not rely on a certificate Config File to generate
 * Certificates
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnitTestCertificateMutator extends CertificateMutator {
    private List<ClientCertificateStructure> clientPairList;
    private List<ServerCertificateStructure> serverPairList;
    private Random r;

    public UnitTestCertificateMutator() {
	this.clientPairList = new ArrayList<>();
	this.serverPairList = new ArrayList<>();
	clientPairList.add(new ClientCertificateStructure("password", "alias", new File("../resources/rsa1024.jks")));
	r = new Random();

	serverPairList.add(new ServerCertificateStructure(new File(
		"../resources/EvolutionaryFuzzer/TestCerts/rsa1024key.pem"), new File(
		"../resources/EvolutionaryFuzzer/TestCerts/rsa1024.pem")));

    }

    @Override
    public ClientCertificateStructure getClientCertificateStructure() {
	return clientPairList.get(r.nextInt(clientPairList.size()));
    }

    @Override
    public ServerCertificateStructure getServerCertificateStructure() {
	return serverPairList.get(r.nextInt(serverPairList.size()));
    }

}
