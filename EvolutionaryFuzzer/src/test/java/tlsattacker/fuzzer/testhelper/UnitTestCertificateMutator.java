/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.testhelper;

import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

/**
 * This mutator does not rely on a certificate Config File to generate
 * Certificates
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnitTestCertificateMutator extends CertificateMutator {

    /**
     *
     */
    private final List<ClientCertificateStructure> clientPairList;

    /**
     *
     */
    private final List<ServerCertificateStructure> serverPairList;

    /**
     *
     */
    private final Random r;

    /**
     *
     */
    public UnitTestCertificateMutator() {
        this.clientPairList = new ArrayList<>();
        this.serverPairList = new ArrayList<>();
        clientPairList.add(new ClientCertificateStructure("password", "alias", new File("../resources/rsa1024.jks")));
        r = new Random();

        serverPairList.add(new ServerCertificateStructure(new File(
                "../resources/EvolutionaryFuzzer/TestCerts/rsa1024key.pem"), new File(
                "../resources/EvolutionaryFuzzer/TestCerts/rsa1024.pem")));

    }

    /**
     * 
     * @return
     */
    @Override
    public ClientCertificateStructure getClientCertificateStructure() {
        return clientPairList.get(r.nextInt(clientPairList.size()));
    }

    /**
     * 
     * @return
     */
    @Override
    public ServerCertificateStructure getServerCertificateStructure() {
        return serverPairList.get(r.nextInt(serverPairList.size()));
    }

    /**
     * 
     * @param structure
     * @return
     */
    @Override
    public boolean isSupported(ServerCertificateStructure structure) {
        return serverPairList.contains(structure);
    }

    private static final Logger LOG = Logger.getLogger(UnitTestCertificateMutator.class.getName());

}
