/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Executor;

import Executor.Executor;
import Agents.Agent;
import Config.ConfigManager;
import Config.EvolutionaryFuzzerConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.Level;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;
import Helper.LogFileIDManager;
import Result.Result;
import Result.ResultContainer;
import Server.TLSServer;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

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
public class TLSExecutor extends Executor
{

    private static final Logger LOG = Logger.getLogger(TLSExecutor.class.getName());

    private final TestVector testVector;
    private final TLSServer server;
    private final TestVector backupVector;
    private final Agent agent;

    /**
     * Constructor for the TLSExecutor
     *
     * @param trace Trace that the Executor should execute
     * @param server Server on which the Executor should execute the Trace
     */
    public TLSExecutor(TestVector testVector, TLSServer server, Agent agent)
    {
        this.testVector = testVector;
        this.server = server;
        this.agent = agent;
        backupVector = (TestVector) UnoptimizedDeepCopy.copy(testVector);
    }

    /**
     * Executes the Trace
     */
    @Override
    public void run()
    {

        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
        TransportHandler transportHandler = null;

        try
        {
            // TODO
            for (ProtocolMessage pm : testVector.getTrace().getProtocolMessages())
            {
                if (pm.getMessageIssuer() == ConnectionEnd.SERVER)
                {
                    if (pm.getClass() != ArbitraryMessage.class)
                    {
                        System.out.println("Wrong message class from server");
                    }
                }
            }

            agent.applicationStart(server);
            GeneralConfig gc = new GeneralConfig();
            gc.setLogLevel(Level.OFF);
            configHandler.initialize(gc);

            EvolutionaryFuzzerConfig fc = ConfigManager.getInstance().getConfig();

            long time = System.currentTimeMillis();
            int counter = 0;
            while (transportHandler == null)
            {
                try
                {

                    transportHandler = configHandler.initializeTransportHandler(fc);

                }
                catch (ConfigurationException E)
                {
                    // It may happen that the implementation is not ready yet
                    if (time + ConfigManager.getInstance().getConfig().getTimeout() < System.currentTimeMillis())
                    {
                        System.out.println("Could not start Server! Trying to Restart it!");
                        agent.applicationStop(server);
                        agent.applicationStart(server);
                        time = System.currentTimeMillis();
                        counter++;
                    }
                    if (counter >= 5)
                    {
                        throw new ConfigurationException("Could not start TLS Server, check your configuration Files!");
                    }
                }
            }
            KeyStore ks = KeystoreHandler.loadKeyStore(fc.getKeystore(), fc.getPassword());
            TlsContext tlsContext = configHandler.initializeTlsContext(ConfigManager.getInstance().getConfig());
            tlsContext.setKeyStore(ks);
            tlsContext.setAlias(fc.getAlias());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = (Collection<? extends Certificate>) certFactory.generateCertificates(new FileInputStream(testVector.getKeyCertPair().getCertificateFile()));

            Certificate sunCert = (Certificate) certs.toArray()[0];
            byte[] certBytes = sunCert.getEncoded();

            ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
            org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);

            org.bouncycastle.asn1.x509.Certificate[] certs2 = new org.bouncycastle.asn1.x509.Certificate[1];
            certs2[0] = cert;
            org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs2);

            X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));

            tlsContext.setX509ServerCertificateObject(x509CertObject);
            tlsContext.setServerCertificate(cert);
            tlsContext.setWorkflowTrace(testVector.getTrace());

            WorkflowExecutor workflowExecutor = new GenericWorkflowExecutor(transportHandler, tlsContext);

            // tlsContext.setServerCertificate(certificate);
            workflowExecutor.executeWorkflow();
        }
        catch (UnsupportedOperationException E)
        {
            // Skip Workflows we dont support yet
        }
        catch (Throwable E)
        {
            File f = new File(ConfigManager.getInstance().getConfig().getOutputFolder() + "faulty/"
                    + LogFileIDManager.getInstance().getFilename());

            try
            {
                f.createNewFile();
                WorkflowTraceSerializer.write(f, testVector.getTrace());
            }
            catch (JAXBException | IOException Ex)
            {
                System.out.println("Could not serialize WorkflowTrace!");
                Ex.printStackTrace();
            }
            System.out.println("File:" + f.getName());
            E.printStackTrace();
        }
        finally
        {
            if (transportHandler != null)
            {
                transportHandler.closeConnection();
            }
            long t = System.currentTimeMillis();
            while (!server.exited())
            {
                if (t + ConfigManager.getInstance().getConfig().getTimeout() < System.currentTimeMillis())
                {
                    // TODO tell agent that server timeout
                    server.stop();
                    break;

                }
            }

            agent.applicationStop(server);
            File branchTrace = new File(server.getTracesFolder().getAbsolutePath() + "/" + server.getID());
            Result r = agent.collectResults(branchTrace, backupVector,testVector);
            branchTrace.delete();
            ResultContainer.getInstance().commit(r);
            int id = server.getID();

            // Cleanup
            File file = new File(server.getTracesFolder().getAbsolutePath() + "/" + id);
            if (file.exists())
            {
                file.delete();
            }
        }

    }

}
