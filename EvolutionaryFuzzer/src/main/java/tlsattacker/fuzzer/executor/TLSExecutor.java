/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.executor;

import tlsattacker.fuzzer.agent.Agent;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.ServerDoesNotStartException;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.Level;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;
import tlsattacker.fuzzer.helper.LogFileIDManager;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.testvector.TestVector;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import de.rub.nds.tlsattacker.dtls.workflow.Dtls12WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import tlsattacker.fuzzer.result.TestVectorResult;

/**
 * This is an Implementation of an Executor. This Executor is specially designed
 * for the TLS Protocol. The whole Program is not completely generic in this
 * Fashion designed, but with a little work the Fuzzer can be adapted for other
 * Programs, as long as a new Executor is designed.
 *
 * It is also possible to Design a new Executor which executes the
 * Workflowtraces with another Library than TLS-Attacker.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSExecutor extends Executor {

    /**
     * The name of the Executor when referred by command line
     */
    public static final String optionName = "tlsexecutor";

    /**
     * The TestVector that the executor should execute
     */
    private final TestVector testVector;

    /**
     * The TLSServer that the Executor should execute the TestVector on
     */
    private final TLSServer server;

    /**
     * The Agent that the Executor should use
     */
    private final Agent agent;

    /**
     * Config object used
     */
    private final EvolutionaryFuzzerConfig config;

    /**
     * Constructor for the TLSExecutor
     *
     * @param config Config that should be used
     * @param testVector TestVector that should be executed
     * @param server Server on which the Executor should execute the Trace
     * @param agent
     */
    public TLSExecutor(EvolutionaryFuzzerConfig config, TestVector testVector, TLSServer server, Agent agent) {
        this.testVector = testVector;
        this.server = server;
        this.agent = agent;
        this.config = config;

    }

    /**
     * Generates a TransportHandler according to the TLSServer and the config
     *
     * @param server TLSServer to use
     * @param config Config to use
     * @return A newly generated Transporthandler
     */
    private TransportHandler generateTransportHandler(TLSServer server, EvolutionaryFuzzerConfig config) {
        TransportHandler th = TransportHandlerFactory.createTransportHandler(config.getTransportHandlerType(),
                config.getTlsTimeout());
        try {
            th.initialize(server.getIp(), server.getPort());
            return th;
        } catch (ArrayIndexOutOfBoundsException | NullPointerException | NumberFormatException ex) {
            throw new ConfigurationException("Server not properly configured!");
        } catch (IOException ex) {
            throw new ConfigurationException("Unable to initialize the transport handler with: " + server.getIp() + ":"
                    + server.getPort(), ex);
        }
    }

    private static final Logger LOG = Logger.getLogger(TLSExecutor.class.getName());

    @Override
    public TestVectorResult call() throws Exception {
        AgentResult result = null;
        try {
            boolean timeout = false;
            ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
            TransportHandler transportHandler = null;

            try {
                //Copy since we need to change values in the config at runtime
                EvolutionaryFuzzerConfig fc = (EvolutionaryFuzzerConfig) UnoptimizedDeepCopy.copy(config);
                // Load clientCertificate
                // TODO This can be a problem when running with mutliple threads
                fc.setKeystore(testVector.getClientKeyCert().getJKSfile().getAbsolutePath());
                fc.setPassword(testVector.getClientKeyCert().getPassword());
                fc.setAlias(testVector.getClientKeyCert().getAlias());
                agent.applicationStart();
                GeneralConfig gc = new GeneralConfig();
                gc.setLogLevel(Level.OFF);
                configHandler.initialize(gc);

                long time = System.currentTimeMillis();
                int counter = 0;
                while (transportHandler == null) {
                    try {
                        transportHandler = generateTransportHandler(server, fc);
                    } catch (ConfigurationException E) {
                        // It may happen that the implementation is not ready
                        // yet
                        if (time + fc.getBootTimeout() < System.currentTimeMillis()) {
                            LOG.log(java.util.logging.Level.FINE, "Could not start Server! Trying to Restart it!");
                            agent.applicationStop();
                            agent.applicationStart();
                            time = System.currentTimeMillis();
                            counter++;
                        }
                        if (counter >= 5) {
                            throw new ConfigurationException(
                                    "Could not start TLS Server, check your configuration Files!");
                        }
                    }
                }
                KeyStore ks = KeystoreHandler.loadKeyStore(fc.getKeystore(), fc.getPassword());
                TlsContext tlsContext = configHandler.initializeTlsContext(fc);
                tlsContext.setFuzzingMode(true);
                tlsContext.setKeyStore(ks);
                tlsContext.setAlias(fc.getAlias());
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certs = certFactory.generateCertificates(new FileInputStream(
                        testVector.getServerKeyCert().getCertificateFile()));

                Certificate sunCert = (Certificate) certs.toArray()[0];
                byte[] certBytes = sunCert.getEncoded();

                ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
                org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
                        .getInstance(asn1Cert);

                org.bouncycastle.asn1.x509.Certificate[] certs2 = new org.bouncycastle.asn1.x509.Certificate[1];
                certs2[0] = cert;
                org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs2);

                X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));

                tlsContext.setX509ServerCertificateObject(x509CertObject);
                tlsContext.setServerCertificate(cert);
                tlsContext.setWorkflowTrace(testVector.getTrace());
                WorkflowExecutor workflowExecutor = null;
                if (testVector.getExecutorType() == ExecutorType.TLS) {
                    workflowExecutor = new GenericWorkflowExecutor(transportHandler, tlsContext,
                            testVector.getExecutorType());
                } else {
                    workflowExecutor = new Dtls12WorkflowExecutor(transportHandler, tlsContext);
                }
                // tlsContext.setServerCertificate(certificate);
                workflowExecutor.executeWorkflow();
            } catch (UnsupportedOperationException E) {
                // Skip Workflows we dont support yet
            } catch (ServerDoesNotStartException E) {
                timeout = true; // TODO
            } catch (Throwable E) {
                File f = new File(config.getOutputFaultyFolder()
                        + LogFileIDManager.getInstance().getFilename());

                try {
                    TestVectorSerializer.write(f, testVector);
                } catch (JAXBException | IOException Ex) {
                    LOG.log(java.util.logging.Level.INFO, "Could not serialize WorkflowTrace:{0}", f.getAbsolutePath());
                    Ex.printStackTrace();
                }
                LOG.log(java.util.logging.Level.INFO, "File:{0}", f.getName());
                E.printStackTrace();
            } finally {
                if (transportHandler != null) {
                    transportHandler.closeConnection();
                }
                agent.applicationStop();
                File branchTrace = new File(config.getTracesFolder().getAbsolutePath()
                        + "/" + server.getID());
                try {
                    result = agent.collectResults(branchTrace, testVector);
                    result.setDidTimeout(timeout);
                    branchTrace.delete();
                } catch (Exception E) {
                    E.printStackTrace();
                }
                int id = server.getID();

                // Cleanup
                File file = new File(config.getTracesFolder().getAbsolutePath() + "/"
                        + id);
                if (file.exists()) {
                    file.delete();
                }
            }
        } finally {
            server.release();
        }
        return new TestVectorResult(testVector, result);
    }
}
