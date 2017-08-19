/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXB;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ForwardActionTest {

    private static final Logger LOGGER = LogManager.getLogger(ForwardActionTest.class);

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private State state;
    private TlsContext ctx1;
    private final String ctx1Alias = "ctx1";
    private TlsContext ctx2;
    private final String ctx2Alias = "ctx2";
    AlertMessage alert;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {

        state = new State();
        alert = new AlertMessage(state.getConfig());
        alert.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        alert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());

        ctx1 = new TlsContext(state.getConfig());
        ctx2 = new TlsContext(state.getConfig());

        state.addTlsContext(ctx1Alias, ctx1);
        state.addTlsContext(ctx2Alias, ctx2);

        FakeTransportHandler th = new FakeTransportHandler(ConnectionEndType.SERVER);
        byte[] alertMsg = new byte[] { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50 };
        th.setFetchableByte(alertMsg);
        ctx1.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        ctx1.setRecordLayer(new TlsRecordLayer(ctx1));
        ctx1.getRecordLayer().setRecordCipher(new RecordBlockCipher(ctx1));
        ctx1.setTransportHandler(th);

        ctx2.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        ctx2.setRecordLayer(new TlsRecordLayer(ctx2));
        ctx2.getRecordLayer().setRecordCipher(new RecordBlockCipher(ctx2));
        ctx2.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    /**
     * Test normal execution.
     */
    @Test
    public void testExecute() throws Exception {
        ForwardAction action = new ForwardAction(alert);

        action.setReceiveFromAlias("ctx1");
        action.setForwardToAlias("ctx2");

        action.execute(state);
        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());
    }

    /**
     * Test execution attempts with missing aliases.
     */
    @Test
    public void testExecuteMissingAliases() throws Exception {
        ForwardAction action = new ForwardAction(alert);

        action.setForwardToAlias(null);
        action.setReceiveFromAlias("set");
        exception.expect(WorkflowExecutionException.class);
        exception.expectMessage("Can't execute ForwardAction with empty forwardToAlias");
        action.execute(state);

        action.setReceiveFromAlias(null);
        action.setForwardToAlias("set");
        exception.expect(WorkflowExecutionException.class);
        exception.expectMessage("Can't execute ForwardAction with empty receiveFromAlias");
        action.execute(state);
    }

    /**
     * TODO Test application data forwarding
     */
    // @Test
    // public void testForwardApplicationMessage() throws Exception {
    // ApplicationMessage msg = new ApplicationMessage(state.getConfig());
    // String data = "Forward application message test";
    // msg.setData(data.getBytes());
    //
    // ForwardAction action = new ForwardAction(msg);
    // action.setReceiveFromAlias("ctx1");
    // action.setForwardToAlias("ctx2");
    //
    // action.execute(state);
    // assertTrue(action.isExecuted());
    // assertTrue(action.executedAsPlanned());
    // }

    /**
     * Test (de-)serialization.
     */
    @Test
    public void testJAXB() {
        ForwardAction action = new ForwardAction(alert);

        action.setReceiveFromAlias("ctx1");
        action.setForwardToAlias("ctx2");

        StringWriter writer = new StringWriter();
        JAXB.marshal(action, writer);
        LOGGER.debug(writer.getBuffer().toString());

        TLSAction action2 = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), ForwardAction.class);
        assertEquals(action, action2);
    }
}
