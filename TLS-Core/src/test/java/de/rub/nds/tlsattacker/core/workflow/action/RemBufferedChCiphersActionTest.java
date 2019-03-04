/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.NoSuchPaddingException;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class RemBufferedChCiphersActionTest {

    private State state;
    private TlsContext ctx;
    private WorkflowTrace trace;

    private ClientHelloMessage ch;
    private ClientHelloPreparator preparator;
    private RemBufferedChCiphersAction action;
    private List<CipherSuite> remove;
    private List<CipherSuite> expected;
    private List<CipherSuite> actual;
    private byte[] expectedBytes;
    private int expectedLength;
    private int expectedMsgLength;
    private byte[] actualBytes;
    private int actualLength;
    private int actualMsgLength;

    public RemBufferedChCiphersActionTest() {
    }

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {

        expected = new ArrayList();
        expected.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        expected.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        expected.add(CipherSuite.SSL_FORTEZZA_KEA_WITH_NULL_SHA);
        expected.add(CipherSuite.TLS_PSK_WITH_RC4_128_SHA);
        expectedBytes = ArrayConverter.hexStringToByteArray("13041302001C008A");
        expectedLength = 8;

        Config config = Config.createConfig();
        config.setDefaultClientSupportedCiphersuites(expected);

        action = new RemBufferedChCiphersAction();
        trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);
        ctx = state.getTlsContext();
        ch = new ClientHelloMessage(config);
        preparator = new ClientHelloPreparator(ctx.getChooser(), ch);
        preparator.prepare();
        expectedMsgLength = ch.getLength().getValue();
        ctx.getMessageBuffer().add(ch);
        remove = new ArrayList<>();
    }

    private void compareFields() {
        actualBytes = ch.getCipherSuites().getValue();
        actualLength = ch.getCipherSuiteLength().getValue();
        actualMsgLength = ch.getLength().getValue();
        assertThat("bytes should be adjusted", actualBytes, equalTo(expectedBytes));
        assertThat("bytes lengths should be adjusted", actualLength, equalTo(expectedLength));
        assertThat("message lengths should be adjusted", actualMsgLength, equalTo(expectedMsgLength));
        assertTrue(action.isExecuted());
    }

    private void setExpectedFields(String ciphersBytes) {
        expectedBytes = ArrayConverter.hexStringToByteArray(ciphersBytes);
        int diff = expectedLength;
        expectedLength = ciphersBytes.length() / 2;
        diff -= expectedLength;
        expectedMsgLength -= diff;
    }

    @Test
    public void removingNothingIsOk() {
        action.execute(state);

        assertTrue(action.isExecuted());
        compareFields();
    }

    @Test
    public void removingSingleExtensionIsOk() {
        expected.remove(CipherSuite.TLS_AES_256_GCM_SHA384);
        setExpectedFields("1304001C008A");

        action.setRemoveCiphers(CipherSuite.TLS_AES_256_GCM_SHA384);
        action.execute(state);

        assertTrue(action.isExecuted());
        compareFields();
    }

    @Test
    public void removingMultipleExtensionsIsOk() {
        remove.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        remove.add(CipherSuite.SSL_FORTEZZA_KEA_WITH_NULL_SHA);
        expected.removeAll(remove);
        setExpectedFields("1302008A");

        action.setRemoveCiphers(remove);
        action.execute(state);

        assertTrue(action.isExecuted());
        compareFields();
    }

    @Test
    public void removingNonProposedExtensionsIsOk() {
        remove.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        remove.add(CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        remove.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        expected.removeAll(remove);
        setExpectedFields("1304001C008A");

        action.setRemoveCiphers(remove);
        action.execute(state);

        assertTrue(action.isExecuted());
        compareFields();
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingEmptyActionYieldsMinimalOutput() {
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(RemBufferedChCiphersAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshaclingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(RemBufferedChCiphersAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        action.setRemoveCiphers(CipherSuite.TLS_AES_128_CCM_SHA256, CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA);
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }

}
