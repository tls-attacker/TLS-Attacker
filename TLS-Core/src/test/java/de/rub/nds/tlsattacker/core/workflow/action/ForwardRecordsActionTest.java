/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.filter.DefaultFilter;
import de.rub.nds.tlsattacker.core.workflow.filter.Filter;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ForwardRecordsActionTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private State state;
    private Config config;
    private TlsContext ctx1;
    private final String ctx1Alias = "ctx1";
    private TlsContext ctx2;
    private final String ctx2Alias = "ctx2";
    private ForwardRecordsAction action;
    private WorkflowTrace trace;

    @Before
    public void setUp() throws Exception {
        config = Config.createConfig();

        trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection(ctx1Alias));
        trace.addConnection(new InboundConnection(ctx2Alias));

        state = new State(config, trace);
        ctx1 = state.getTlsContext(ctx1Alias);
        ctx2 = state.getTlsContext(ctx2Alias);

        FakeTransportHandler th = new FakeTransportHandler(ConnectionEndType.SERVER);
        byte[] alertMsg = new byte[] { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32 };
        th.setFetchableByte(alertMsg);
        ctx1.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        ctx1.setRecordLayer(new TlsRecordLayer(ctx1));
        ctx1.setTransportHandler(th);

        ctx2.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        ctx2.setRecordLayer(new TlsRecordLayer(ctx2));
        ctx2.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    @Test
    public void executingSetsExecutionFlagsCorrectly() throws Exception {
        action = new ForwardRecordsAction(ctx1Alias, ctx2Alias);
        action.execute(state);
        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());
    }

    @Test(expected = WorkflowExecutionException.class)
    public void executingTwiceThrowsException() throws Exception {
        action = new ForwardRecordsAction(ctx1Alias, ctx2Alias);
        action.execute(state);
        assertTrue(action.isExecuted());
        action.execute(state);
    }

    @Test(expected = WorkflowExecutionException.class)
    public void executingWithNullAliasThrowsException() throws Exception {
        action = new ForwardRecordsAction(null, ctx2Alias);
        action.execute(state);
    }

    @Test(expected = WorkflowExecutionException.class)
    public void executingWithEmptyAliasThrowsException() throws Exception {
        action = new ForwardRecordsAction("", ctx2Alias);
        action.execute(state);
    }

    @Test
    public void marshalingEmptyActionYieldsMinimalOutput() {
        try {
            action = new ForwardRecordsAction(ctx1Alias, ctx2Alias);
            trace.addTlsAction(action);

            // used PrintWriter and not StringBuilder as it offers
            // OS-independent functionality for printing new lines
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            pw.println("<workflowTrace>");
            pw.println("    <OutboundConnection>");
            pw.println("        <alias>ctx1</alias>");
            pw.println("    </OutboundConnection>");
            pw.println("    <InboundConnection>");
            pw.println("        <alias>ctx2</alias>");
            pw.println("    </InboundConnection>");
            pw.println("    <ForwardRecords>");
            pw.println("        <actionOptions/>");
            pw.println("        <from>ctx1</from>");
            pw.println("        <to>ctx2</to>");
            pw.println("    </ForwardRecords>");
            pw.println("</workflowTrace>");
            pw.close();
            String expected = sw.toString();

            Filter filter = new DefaultFilter(config);
            filter.applyFilter(trace);
            filter.postFilter(trace, state.getOriginalWorkflowTrace());
            String actual = WorkflowTraceSerializer.write(trace);
            LOGGER.info(actual);
            Assert.assertThat(actual, equalTo(expected));

        } catch (JAXBException | IOException ex) {
            LOGGER.error(ex.getLocalizedMessage(), ex);
            Assert.fail();
        }
    }

    @Test
    public void marshalingAndUnmarshalingYieldsEqualObject() {
        action = new ForwardRecordsAction(ctx1Alias, ctx2Alias);
        StringWriter writer = new StringWriter();
        JAXB.marshal(action, writer);
        TlsAction actual = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), ForwardRecordsAction.class);
        assertEquals(action, actual);
    }
}
