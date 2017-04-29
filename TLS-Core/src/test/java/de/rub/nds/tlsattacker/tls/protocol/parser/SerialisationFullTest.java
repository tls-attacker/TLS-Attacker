/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tests.IntegrationTests;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.tls.record.AbstractRecord;
import de.rub.nds.tlsattacker.tls.record.BlobRecord;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.util.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeCompressionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangePreMasterSecretAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerRandomAction;
import de.rub.nds.tlsattacker.tls.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import static org.junit.Assert.fail;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.TemporaryFolder;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SerialisationFullTest {

    protected static final Logger LOGGER = LogManager.getLogger("Test");

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    public SerialisationFullTest() {
    }

    @Test
    @Category(IntegrationTests.class)
    public void test() throws JAXBException, IOException {
        TlsConfig config = TlsConfig.createConfig();
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddHeartbeatExtension(true);
        config.setAddMaxFragmentLengthExtenstion(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgrorithmsExtension(true);
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createFullWorkflow();
        trace.add(new ChangeCipherSuiteAction(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA));
        trace.add(new ChangeClientCertificateAction(Certificate.EMPTY_CHAIN));
        trace.add(new ChangeClientRandomAction(new byte[] { 0x00, 0x11, 0x22, 0x33 }));
        trace.add(new ChangeCompressionAction(CompressionMethod.LZS));
        trace.add(new ChangeMasterSecretAction(new byte[] { 0x00, 0x22, 0x44, 0x66, 0x44 }));
        trace.add(new ChangePreMasterSecretAction(new byte[] { 0x33, 0x66, 0x55, 0x44, }));
        trace.add(new ChangeProtocolVersionAction(ProtocolVersion.SSL3));
        trace.add(new ChangeServerCertificateAction(Certificate.EMPTY_CHAIN));
        trace.add(new ChangeServerRandomAction(new byte[] { 0x77, 0x77, 0x77, 0x77, 0x77 }));
        trace.add(new DeactivateEncryptionAction());
        trace.add(new RenegotiationAction());
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new AlertMessage());
        messages.add(new ApplicationMessage());
        messages.add(new ArbitraryMessage());
        messages.add(new CertificateMessage());
        messages.add(new CertificateRequestMessage());
        messages.add(new CertificateVerifyMessage());
        messages.add(new ChangeCipherSpecMessage());
        messages.add(new ClientHelloMessage());
        messages.add(new DHClientKeyExchangeMessage());
        messages.add(new DHEServerKeyExchangeMessage());
        messages.add(new ECDHClientKeyExchangeMessage());
        messages.add(new ECDHEServerKeyExchangeMessage());
        messages.add(new FinishedMessage());
        messages.add(new HeartbeatMessage());
        messages.add(new HelloRequestMessage());
        messages.add(new HelloVerifyRequestMessage());
        messages.add(new RSAClientKeyExchangeMessage());
        messages.add(new RetransmitMessage());
        messages.add(new SSL2ClientHelloMessage());
        messages.add(new SSL2ServerHelloMessage());
        messages.add(new ServerHelloDoneMessage());
        messages.add(new UnknownHandshakeMessage());
        messages.add(new UnknownMessage());
        messages.add(new ServerHelloMessage());
        SendAction action = new SendAction(messages);
        List<AbstractRecord> records = new LinkedList<AbstractRecord>();
        records.add(new BlobRecord());
        records.add(new Record());
        action.setConfiguredRecords(records);
        trace.add(action);

        File f = folder.newFile();
        WorkflowTraceSerializer.write(f, trace);
        BufferedReader reader = new BufferedReader(new FileReader(f));
        String line = null;
        StringBuilder builder = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            builder.append("\n" + line);
        }
        LOGGER.debug(builder.toString());
        try {
            trace = WorkflowTraceSerializer.read(new FileInputStream(f));
        } catch (XMLStreamException ex) {
            fail();
        }
    }
}
