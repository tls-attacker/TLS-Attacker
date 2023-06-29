/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import jakarta.xml.bind.JAXB;
import java.io.StringReader;
import java.io.StringWriter;
import org.junit.After;
import org.junit.Test;
import org.junit.jupiter.api.Tag;

public class TightReceiveActionTest {

    private State state;
    private TlsContext tlsContext;

    private TightReceiveAction action;

    private void prepareTrace() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(trace);

        tlsContext = state.getTlsContext();
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.SERVER));
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    }

    @After
    public void tearDown() {}

    /**
     * Test of execute method of class TightReceiveAction.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testExecute() throws Exception {
        action = new TightReceiveAction(new AlertMessage());
        prepareTrace();
        ((FakeTransportHandler) tlsContext.getTransportHandler())
                .setFetchableByte(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50});

        action.execute(state);
        assertTrue(action.executedAsPlanned());
        assertEquals(1, action.getReceivedMessages().size());
        AlertMessage expectedAlert = getAlertMessage();
        assertEquals(expectedAlert, action.getReceivedMessages().get(0));
    }

    private AlertMessage getAlertMessage() {
        AlertMessage expectedAlert = new AlertMessage();
        expectedAlert.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        expectedAlert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        expectedAlert.setLevel(AlertLevel.FATAL.getValue());
        return expectedAlert;
    }

    /**
     * Test of execute method of class TightReceiveAction with multiple messages.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testExecuteMultipleInOneRecord() throws Exception {
        action = new TightReceiveAction(new ServerHelloMessage(), new CertificateMessage());
        prepareTrace();
        ((FakeTransportHandler) tlsContext.getTransportHandler())
                .setFetchableByte(
                        ArrayConverter.hexStringToByteArray(
                                "160303057C0200003d03039277b6fc9c6db40b2e58f5c647b797cb116d96db19f38d25444f574e4752440100c030000015ff01000100000b00040300010200230000001700000b000407000404000401308203fd308202e5a00302010202147c2ab982ca69550cb5daa3c62bf237b1d929c8ba300d06092a864886f70d01010b050030818d310b30090603550406130249493113301106035504080c0ac383c29670656e53534c3142304006035504070c39c390c2a1c390c2b0c390c2bdc390c2bac391c2822dc390c29fc390c2b5c391c282c390c2b5c391c280c390c2b1c391c283c391c280c390c2b33111300f060355040a0c0842524420476d62483112301006035504030c096c6f63616c686f7374301e170d3231303932313036353632385a170d3232303932313036353632385a30818d310b30090603550406130249493113301106035504080c0ac383c29670656e53534c3142304006035504070c39c390c2a1c390c2b0c390c2bdc390c2bac391c2822dc390c29fc390c2b5c391c282c390c2b5c391c280c390c2b1c391c283c391c280c390c2b33111300f060355040a0c0842524420476d62483112301006035504030c096c6f63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100d5dad4742330b1a6bebc5165ae5e8d9410e70355b752270a14a4942438fd5af2ee18211eb114416865bd3676cc666a3017eb531ed4cdb6177ed9238d9dbfbcd833bd9d0d53f81bf75c8743ae02dc598be5ba7ef12b49137eb9e0c4735ac7a1ac7535d2b76fa574f8d1bf91dbbc3b5b46d65beba50a1e7dd3963ab9a9c8d52e96b5c2613cec713b2c638f7120fdfb70ca82c8ed9a9faf9086bcf63c20db6311851241f8035e399403ccd07767a63c2c3863736a2eb61ed61a45dbb0f65fb7fc65ba0219453db8ec0e13a255c803db12513592ae865aa814a1009c76d94fc06eab928126a11fc0e1fe1ad27f492d53398f916eb3cb0dc5c9a1bca455f84c02f5a10203010001a3533051301d0603551d0e041604140503e9de537c006989ef8032aa17da54fcb0f9bf301f0603551d230418301680140503e9de537c006989ef8032aa17da54fcb0f9bf300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038201010092fc82bb8a383b9a3d4a89d2dce033e660710b7fc22986eee968536b85100d9e847a1e00ac39aa6e206ed0afa0c01cc354fcf876ffdc37bfbbd80857e2ca85e0a61d293b97fa96b4b5ddd10c264c51b54ecaf79ef3b500e44b540e4ab7669e43b29dd0ebff97ed5a378d4d825e9204e059010e2d8c032d42ee213ed665e70f35bd57d396d3a21d3afae779464387334caaff0013a16d1fe2eb67c9f9eb4689062b8d614ddf6a737dec6fa8999a8cbbee00d0ade05a468c95a644b338f1762446b05f1dce4df92de78dbbe43d52cf033aac1c399ba2ebb072674a09ccb0733c179d0fff8f263f6e8d00c83c28935d6217ee1be64d9bbdb11c530d36a11ea2bd340c00012803001d20fc551a7c315b844f2c0b8fb0845da35af812626bcf88aed6d85d6f28baa68b1c080401001bfd18e18faaa967d0ea2e7bf3ccb82012be2b877fa113a0d40d20ba1dc7d41eeac8d1ce78d94856bb4688646cba802b70499dbb017fa0b3ace988a5b238f6f582436e53f2c44b97b632df435d62f7e31ecf636ba5c65ed0678a4e98641e2a56eecea2f2ce3de927e5342bfaa1cbf2e4048e304c5c9ce29d6306fa8859f0e70cf9591de8167f7eacce265cfeb78fb53285b5fcfee89b9eb4137dadddadba16346d761f13accaaef3fdc58bf52edd36a9ba0cfe9dbd2cba113ba9b775cd1d150f524aa4678b294d741b074b5512ed918ee5db46c468223b5e966da44be21f27baee118edc7fd6eba31e3999185bca43b84d838b718d941ffd77427ab9239c498b0e000000"));
        testAction();
    }

    /**
     * Test of execute method of class TightReceiveAction with multiple messages in separate
     * records.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testExecuteMultipleIndividualRecords() throws Exception {
        action = new TightReceiveAction(new ServerHelloMessage(), new CertificateMessage());
        prepareTrace();
        ((FakeTransportHandler) tlsContext.getTransportHandler())
                .setFetchableByte(
                        ArrayConverter.hexStringToByteArray(
                                "16030300410200003d03039277b6fc9c6db40b2e58f5c647b797cb116d96db19f38d25444f574e4752440100c030000015ff01000100000b0004030001020023000000170000160303040b0b000407000404000401308203fd308202e5a00302010202147c2ab982ca69550cb5daa3c62bf237b1d929c8ba300d06092a864886f70d01010b050030818d310b30090603550406130249493113301106035504080c0ac383c29670656e53534c3142304006035504070c39c390c2a1c390c2b0c390c2bdc390c2bac391c2822dc390c29fc390c2b5c391c282c390c2b5c391c280c390c2b1c391c283c391c280c390c2b33111300f060355040a0c0842524420476d62483112301006035504030c096c6f63616c686f7374301e170d3231303932313036353632385a170d3232303932313036353632385a30818d310b30090603550406130249493113301106035504080c0ac383c29670656e53534c3142304006035504070c39c390c2a1c390c2b0c390c2bdc390c2bac391c2822dc390c29fc390c2b5c391c282c390c2b5c391c280c390c2b1c391c283c391c280c390c2b33111300f060355040a0c0842524420476d62483112301006035504030c096c6f63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100d5dad4742330b1a6bebc5165ae5e8d9410e70355b752270a14a4942438fd5af2ee18211eb114416865bd3676cc666a3017eb531ed4cdb6177ed9238d9dbfbcd833bd9d0d53f81bf75c8743ae02dc598be5ba7ef12b49137eb9e0c4735ac7a1ac7535d2b76fa574f8d1bf91dbbc3b5b46d65beba50a1e7dd3963ab9a9c8d52e96b5c2613cec713b2c638f7120fdfb70ca82c8ed9a9faf9086bcf63c20db6311851241f8035e399403ccd07767a63c2c3863736a2eb61ed61a45dbb0f65fb7fc65ba0219453db8ec0e13a255c803db12513592ae865aa814a1009c76d94fc06eab928126a11fc0e1fe1ad27f492d53398f916eb3cb0dc5c9a1bca455f84c02f5a10203010001a3533051301d0603551d0e041604140503e9de537c006989ef8032aa17da54fcb0f9bf301f0603551d230418301680140503e9de537c006989ef8032aa17da54fcb0f9bf300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038201010092fc82bb8a383b9a3d4a89d2dce033e660710b7fc22986eee968536b85100d9e847a1e00ac39aa6e206ed0afa0c01cc354fcf876ffdc37bfbbd80857e2ca85e0a61d293b97fa96b4b5ddd10c264c51b54ecaf79ef3b500e44b540e4ab7669e43b29dd0ebff97ed5a378d4d825e9204e059010e2d8c032d42ee213ed665e70f35bd57d396d3a21d3afae779464387334caaff0013a16d1fe2eb67c9f9eb4689062b8d614ddf6a737dec6fa8999a8cbbee00d0ade05a468c95a644b338f1762446b05f1dce4df92de78dbbe43d52cf033aac1c399ba2ebb072674a09ccb0733c179d0fff8f263f6e8d00c83c28935d6217ee1be64d9bbdb11c530d36a11ea2bd34160303012c0c00012803001d20fc551a7c315b844f2c0b8fb0845da35af812626bcf88aed6d85d6f28baa68b1c080401001bfd18e18faaa967d0ea2e7bf3ccb82012be2b877fa113a0d40d20ba1dc7d41eeac8d1ce78d94856bb4688646cba802b70499dbb017fa0b3ace988a5b238f6f582436e53f2c44b97b632df435d62f7e31ecf636ba5c65ed0678a4e98641e2a56eecea2f2ce3de927e5342bfaa1cbf2e4048e304c5c9ce29d6306fa8859f0e70cf9591de8167f7eacce265cfeb78fb53285b5fcfee89b9eb4137dadddadba16346d761f13accaaef3fdc58bf52edd36a9ba0cfe9dbd2cba113ba9b775cd1d150f524aa4678b294d741b074b5512ed918ee5db46c468223b5e966da44be21f27baee118edc7fd6eba31e3999185bca43b84d838b718d941ffd77427ab9239c498b16030300040e000000"));
        testAction();
    }

    private void testAction() throws WorkflowExecutionException {
        action.execute(state);
        assertTrue(action.executedAsPlanned());
        assertEquals(2, action.getReceivedMessages().size());
        assertTrue(action.getReceivedMessages().get(0) instanceof ServerHelloMessage);
        assertTrue(action.getReceivedMessages().get(1) instanceof CertificateMessage);
        assertTrue(action.isExecuted());
    }

    /** Test of execute method, of class TightReceiveAction. */
    @Test
    public void testReset() {
        action = new TightReceiveAction(getAlertMessage());
        prepareTrace();
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
    }

    @Test
    public void testJAXB() {
        action = new TightReceiveAction(getAlertMessage());
        prepareTrace();
        StringWriter writer = new StringWriter();
        action.filter();
        JAXB.marshal(action, writer);
        TlsAction action2 =
                JAXB.unmarshal(
                        new StringReader(writer.getBuffer().toString()), TightReceiveAction.class);
        action.normalize();
        action2.normalize();
        assertThat(action, equalTo(action2));
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void marshalingEmptyActionYieldsMinimalOutput() {
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(TightReceiveAction.class);
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(
                TightReceiveAction.class);
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }
}
