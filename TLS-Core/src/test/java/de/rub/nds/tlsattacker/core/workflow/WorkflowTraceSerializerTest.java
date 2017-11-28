/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.singlebyte.ByteExplicitValueModification;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.unittest.helper.DefaultNormalizeFilter;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class WorkflowTraceSerializerTest {

    private static final Logger LOGGER = LogManager.getLogger(WorkflowTraceSerializerTest.class);

    Config config;
    MessageAction action;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Before
    public void setUp() throws JAXBException {
        config = Config.createConfig();
        action = new SendAction(new ClientHelloMessage(Config.createConfig()));
    }

    /**
     * Test of write method, of class WorkflowTraceSerializer.
     *
     * @throws java.lang.Exception
     */
    // TODO Test all messages with all modifiable variables
    @Test
    public void testWriteRead() throws Exception {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.FULL, RunningModeType.CLIENT);
        // pick random protocol message and initialize a record with modifiable
        // variable
        List<AbstractRecord> records = new LinkedList<>();
        Record record = new Record();
        record.setContentType(new ModifiableByte());
        record.getContentType().setModification(new ByteExplicitValueModification(Byte.MIN_VALUE));
        record.setMaxRecordLengthConfig(5);
        records.add(record);
        action = new SendAction(new ClientHelloMessage());
        action.setRecords(records);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(os, trace);
        LOGGER.debug(new String(os.toByteArray()));

        String serializedWorkflow = new String(os.toByteArray());

        ByteArrayInputStream bis = new ByteArrayInputStream(serializedWorkflow.getBytes());
        WorkflowTrace wt = WorkflowTraceSerializer.read(bis);

        os = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(os, wt);
        LOGGER.debug(new String(os.toByteArray()));

        Assert.assertArrayEquals("The serialized workflows have to be equal", serializedWorkflow.getBytes(),
                os.toByteArray());
    }

    @Test
    public void testWrite() {
        try {
            WorkflowTrace trace = new WorkflowTrace();
            action = new SendAction(new ClientHelloMessage(config));
            trace.addTlsAction(action);
            File f = folder.newFile();
            WorkflowTraceSerializer.write(f, trace);
            Assert.assertTrue(f.exists());
        } catch (JAXBException | IOException ex) {
            LOGGER.error(ex.getLocalizedMessage(), ex);
            Assert.fail();
        }
    }

    /**
     * Verify that serialized/XML with default connection end looks as expected.
     * If there is no custom connection end defined in the workflow trace, the
     * default connection end from the config should be used. The default
     * connection end should not appear in the serialized workflow trace.
     */
    @Test
    public void serializeWithSingleConnectionTest() {
        try {

            WorkflowTrace trace = new WorkflowTrace();
            action = new SendAction(new ClientHelloMessage(config));
            trace.addTlsAction(action);

            StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
            sb.append("<workflowTrace>\n");
            sb.append("    <Send>\n");
            sb.append("        <messages>\n");
            sb.append("            <ClientHello>\n");
            sb.append("                <extensions>\n");
            sb.append("                    <ECPointFormat/>\n");
            sb.append("                    <EllipticCurves/>\n");
            sb.append("                    <RenegotiationInfoExtension/>\n");
            sb.append("                </extensions>\n");
            sb.append("            </ClientHello>\n");
            sb.append("        </messages>\n");
            sb.append("    </Send>\n");
            sb.append("</workflowTrace>\n");
            String expected = sb.toString();

            DefaultNormalizeFilter.normalizeAndFilter(trace, config);
            String actual = WorkflowTraceSerializer.write(trace);
            LOGGER.info(actual);
            Assert.assertEquals(actual, expected);

        } catch (JAXBException | IOException ex) {
            LOGGER.error(ex.getLocalizedMessage(), ex);
            Assert.fail();
        }
    }

    /**
     * Verify that serialized/XML representation with single custom connection
     * end looks as expected.
     */
    @Test
    public void serializeWithSingleCustomConnectionTest() {
        try {

            WorkflowTrace trace = new WorkflowTrace();
            AliasedConnection con = new OutboundConnection("theAlias", 1111, "host1111");
            trace.addConnection(con);
            action = new SendAction(new ClientHelloMessage(config));
            action.setConnectionAlias(con.getAlias());
            trace.addTlsAction(action);

            StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
            sb.append("<workflowTrace>\n");
            sb.append("    <OutboundConnection>\n");
            sb.append("        <alias>theAlias</alias>\n");
            sb.append("        <port>1111</port>\n");
            sb.append("        <hostname>host1111</hostname>\n");
            sb.append("    </OutboundConnection>\n");
            sb.append("    <Send>\n");
            sb.append("        <messages>\n");
            sb.append("            <ClientHello>\n");
            sb.append("                <extensions>\n");
            sb.append("                    <ECPointFormat/>\n");
            sb.append("                    <EllipticCurves/>\n");
            sb.append("                    <RenegotiationInfoExtension/>\n");
            sb.append("                </extensions>\n");
            sb.append("            </ClientHello>\n");
            sb.append("        </messages>\n");
            sb.append("    </Send>\n");
            sb.append("</workflowTrace>\n");
            String expected = sb.toString();

            DefaultNormalizeFilter.normalizeAndFilter(trace, config);
            String actual = WorkflowTraceSerializer.write(trace);
            Assert.assertEquals(expected, actual);

        } catch (JAXBException | IOException ex) {
            LOGGER.error(ex.getLocalizedMessage(), ex);
            Assert.fail();
        }
    }

    /**
     * Verify that serialized/XML representation with multiple connection ends
     * looks as expected.
     */
    @Test
    public void serializeWithMultipleCustomConnectionTest() {
        try {

            WorkflowTrace trace = new WorkflowTrace();
            AliasedConnection con1 = new OutboundConnection("alias1", 1111, "host1111");
            AliasedConnection con2 = new OutboundConnection("alias2", 1122, "host2222");
            AliasedConnection con3 = new InboundConnection("alias3", 1313);
            trace.addConnection(con1);
            trace.addConnection(con2);
            trace.addConnection(con3);
            action = new SendAction(con3.getAlias(), new ClientHelloMessage(config));
            trace.addTlsAction(action);

            StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
            sb.append("<workflowTrace>\n");
            sb.append("    <OutboundConnection>\n");
            sb.append("        <alias>alias1</alias>\n");
            sb.append("        <port>1111</port>\n");
            sb.append("        <hostname>host1111</hostname>\n");
            sb.append("    </OutboundConnection>\n");
            sb.append("    <OutboundConnection>\n");
            sb.append("        <alias>alias2</alias>\n");
            sb.append("        <port>1122</port>\n");
            sb.append("        <hostname>host2222</hostname>\n");
            sb.append("    </OutboundConnection>\n");
            sb.append("    <InboundConnection>\n");
            sb.append("        <alias>alias3</alias>\n");
            sb.append("        <port>1313</port>\n");
            sb.append("    </InboundConnection>\n");
            sb.append("    <Send>\n");
            sb.append("        <connectionAlias>alias3</connectionAlias>\n");
            sb.append("        <messages>\n");
            sb.append("            <ClientHello>\n");
            sb.append("                <extensions>\n");
            sb.append("                    <ECPointFormat/>\n");
            sb.append("                    <EllipticCurves/>\n");
            sb.append("                    <RenegotiationInfoExtension/>\n");
            sb.append("                </extensions>\n");
            sb.append("            </ClientHello>\n");
            sb.append("        </messages>\n");
            sb.append("    </Send>\n");
            sb.append("</workflowTrace>\n");
            String expected = sb.toString();

            DefaultNormalizeFilter.normalizeAndFilter(trace, config);
            String actual = WorkflowTraceSerializer.write(trace);
            Assert.assertEquals(expected, actual);

        } catch (JAXBException | IOException ex) {
            LOGGER.error(ex.getLocalizedMessage(), ex);
            Assert.fail();
        }
    }
}
