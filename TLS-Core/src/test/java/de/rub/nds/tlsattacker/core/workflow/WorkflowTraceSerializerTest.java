/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.singlebyte.ByteExplicitValueModification;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.unittest.helper.DefaultNormalizeFilter;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import jakarta.xml.bind.JAXBException;
import java.io.*;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class WorkflowTraceSerializerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    Config config;
    MessageAction action;

    @BeforeEach
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
        WorkflowTrace trace =
                factory.createWorkflowTrace(WorkflowTraceType.FULL, RunningModeType.CLIENT);
        // pick random protocol message and initialize a record with modifiable
        // variable
        List<Record> records = new LinkedList<>();
        Record record = new Record();
        record.setContentType(new ModifiableByte());
        record.getContentType().setModification(new ByteExplicitValueModification(Byte.MIN_VALUE));
        record.setMaxRecordLengthConfig(5);
        records.add(record);
        action = new SendAction(new ClientHelloMessage());
        action.setRecords(records);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(os, trace);
        LOGGER.debug(os.toString());

        String serializedWorkflow = os.toString();

        ByteArrayInputStream bis = new ByteArrayInputStream(serializedWorkflow.getBytes());
        WorkflowTrace wt = WorkflowTraceSerializer.secureRead(bis);

        os = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(os, wt);
        LOGGER.debug(os.toString());

        assertArrayEquals(
                serializedWorkflow.getBytes(),
                os.toByteArray(),
                "The serialized workflows have to be equal");
    }

    @Test
    public void testWrite(@TempDir File tempDir) throws IOException, JAXBException {
        WorkflowTrace trace = new WorkflowTrace();
        action = new SendAction(new ClientHelloMessage(config));
        trace.addTlsAction(action);
        File f = new File(tempDir, "testWriteWorkflowTrace.xml");
        assert f.exists() || f.createNewFile();
        WorkflowTraceSerializer.write(f, trace);
        assertTrue(f.exists());
    }

    /**
     * Verify that serialized/XML with default connection end looks as expected. If there is no
     * custom connection end defined in the workflow trace, the default connection end from the
     * config should be used. The default connection end should not appear in the serialized
     * workflow trace.
     */
    @Test
    public void serializeWithSingleConnectionTest() throws JAXBException, IOException {
        WorkflowTrace trace = new WorkflowTrace();
        action = new SendAction(new ClientHelloMessage(config));
        trace.addTlsAction(action);

        // used PrintWriter and not StringBuilder as it offers
        // OS-independent functionality for printing new lines
        StringWriter sw = new StringWriter();
        try (PrintWriter pw = new PrintWriter(sw)) {
            pw.println("<workflowTrace>");
            pw.println("    <Send>");
            pw.println("        <actionOptions/>");
            pw.println("        <messages>");
            pw.println("            <ClientHello>");
            pw.println("                <extensions>");
            pw.println("                    <ECPointFormat/>");
            pw.println("                    <EllipticCurves/>");
            pw.println("                    <SignatureAndHashAlgorithmsExtension/>");
            pw.println("                    <RenegotiationInfoExtension/>");
            pw.println("                </extensions>");
            pw.println("            </ClientHello>");
            pw.println("        </messages>");
            pw.println("    </Send>");
            pw.println("</workflowTrace>");
        }
        String expected = sw.toString();

        DefaultNormalizeFilter.normalizeAndFilter(trace, config);
        String actual = WorkflowTraceSerializer.write(trace);
        LOGGER.info(actual);
        assertEquals(expected, actual);
    }

    /**
     * Verify that serialized/XML representation with single custom connection end looks as
     * expected.
     */
    @Test
    public void serializeWithSingleCustomConnectionTest() throws JAXBException, IOException {
        WorkflowTrace trace = new WorkflowTrace();
        AliasedConnection con = new OutboundConnection("theAlias", 1111, "host1111");
        trace.addConnection(con);
        action = new SendAction(new ClientHelloMessage(config));
        action.setConnectionAlias(con.getAlias());
        trace.addTlsAction(action);

        StringWriter sw = new StringWriter();
        try (PrintWriter pw = new PrintWriter(sw)) {
            pw.println("<workflowTrace>");
            pw.println("    <OutboundConnection>");
            pw.println("        <alias>theAlias</alias>");
            pw.println("        <port>1111</port>");
            pw.println("        <hostname>host1111</hostname>");
            pw.println("    </OutboundConnection>");
            pw.println("    <Send>");
            pw.println("        <actionOptions/>");
            pw.println("        <messages>");
            pw.println("            <ClientHello>");
            pw.println("                <extensions>");
            pw.println("                    <ECPointFormat/>");
            pw.println("                    <EllipticCurves/>");
            pw.println("                    <SignatureAndHashAlgorithmsExtension/>");
            pw.println("                    <RenegotiationInfoExtension/>");
            pw.println("                </extensions>");
            pw.println("            </ClientHello>");
            pw.println("        </messages>");
            pw.println("    </Send>");
            pw.println("</workflowTrace>");
        }
        String expected = sw.toString();

        DefaultNormalizeFilter.normalizeAndFilter(trace, config);
        String actual = WorkflowTraceSerializer.write(trace);
        assertEquals(expected, actual);
    }

    /**
     * Verify that serialized/XML representation with multiple connection ends looks as expected.
     */
    @Test
    public void serializeWithMultipleCustomConnectionTest() throws JAXBException, IOException {
        WorkflowTrace trace = new WorkflowTrace();
        AliasedConnection con1 = new OutboundConnection("alias1", 1111, "host1111");
        AliasedConnection con2 = new OutboundConnection("alias2", 1122, "host2222");
        AliasedConnection con3 = new InboundConnection("alias3", 1313);
        trace.addConnection(con1);
        trace.addConnection(con2);
        trace.addConnection(con3);
        action = new SendAction(con3.getAlias(), new ClientHelloMessage(config));
        trace.addTlsAction(action);

        StringWriter sw = new StringWriter();
        try (PrintWriter pw = new PrintWriter(sw)) {
            pw.println("<workflowTrace>");
            pw.println("    <OutboundConnection>");
            pw.println("        <alias>alias1</alias>");
            pw.println("        <port>1111</port>");
            pw.println("        <hostname>host1111</hostname>");
            pw.println("    </OutboundConnection>");
            pw.println("    <OutboundConnection>");
            pw.println("        <alias>alias2</alias>");
            pw.println("        <port>1122</port>");
            pw.println("        <hostname>host2222</hostname>");
            pw.println("    </OutboundConnection>");
            pw.println("    <InboundConnection>");
            pw.println("        <alias>alias3</alias>");
            pw.println("        <port>1313</port>");
            pw.println("    </InboundConnection>");
            pw.println("    <Send>");
            pw.println("        <actionOptions/>");
            pw.println("        <connectionAlias>alias3</connectionAlias>");
            pw.println("        <messages>");
            pw.println("            <ClientHello>");
            pw.println("                <extensions>");
            pw.println("                    <ECPointFormat/>");
            pw.println("                    <EllipticCurves/>");
            pw.println("                    <SignatureAndHashAlgorithmsExtension/>");
            pw.println("                    <RenegotiationInfoExtension/>");
            pw.println("                </extensions>");
            pw.println("            </ClientHello>");
            pw.println("        </messages>");
            pw.println("    </Send>");
            pw.println("</workflowTrace>");
        }
        String expected = sw.toString();

        DefaultNormalizeFilter.normalizeAndFilter(trace, config);
        String actual = WorkflowTraceSerializer.write(trace);
        assertEquals(expected, actual);
    }
}
