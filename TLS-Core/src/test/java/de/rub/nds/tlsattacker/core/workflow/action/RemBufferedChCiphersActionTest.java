/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class RemBufferedChCiphersActionTest extends AbstractActionTest<RemBufferedChCiphersAction> {

    private final ClientHelloMessage ch;
    private final List<CipherSuite> remove;
    private final List<CipherSuite> expected;
    private byte[] expectedBytes;
    private int expectedLength;
    private int expectedMsgLength;

    RemBufferedChCiphersActionTest() {
        super(new RemBufferedChCiphersAction(), RemBufferedChCiphersAction.class);
        expected = new ArrayList<>();
        expected.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        expected.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        expected.add(CipherSuite.SSL_FORTEZZA_KEA_WITH_NULL_SHA);
        expected.add(CipherSuite.TLS_PSK_WITH_RC4_128_SHA);
        expectedBytes = ArrayConverter.hexStringToByteArray("13041302001C008A");
        expectedLength = 8;
        TlsContext context = state.getTlsContext();
        context.getConfig().setDefaultClientSupportedCipherSuites(expected);
        ch = new ClientHelloMessage(config);
        new ClientHelloPreparator(context.getChooser(), ch).prepare();
        expectedMsgLength = ch.getLength().getValue();
        context.getMessageBuffer().add(ch);
        remove = new ArrayList<>();
    }

    private void compareFields() {
        byte[] actualBytes = ch.getCipherSuites().getValue();
        int actualLength = ch.getCipherSuiteLength().getValue();
        int actualMsgLength = ch.getLength().getValue();
        assertArrayEquals(expectedBytes, actualBytes, "bytes should be adjusted");
        assertEquals(expectedLength, actualLength, "bytes lengths should be adjusted");
        assertEquals(expectedMsgLength, actualMsgLength, "message lengths should be adjusted");
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
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        compareFields();
    }

    @Test
    public void testRemoveSingleCipherIsOk() throws Exception {
        expected.remove(CipherSuite.TLS_AES_256_GCM_SHA384);
        setExpectedFields("1304001C008A");
        action.setRemoveCiphers(CipherSuite.TLS_AES_256_GCM_SHA384);
        super.testExecute();
        compareFields();
    }

    @Test
    public void testRemoveMultipleCiphersIsOk() throws Exception {
        remove.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        remove.add(CipherSuite.SSL_FORTEZZA_KEA_WITH_NULL_SHA);
        expected.removeAll(remove);
        setExpectedFields("1302008A");
        action.setRemoveCiphers(remove);
        super.testExecute();
        compareFields();
    }

    @Test
    public void testRemoveNonProposedCiphersIsOk() throws Exception {
        remove.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        remove.add(CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        remove.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        expected.removeAll(remove);
        setExpectedFields("1304001C008A");
        action.setRemoveCiphers(remove);
        super.testExecute();
        compareFields();
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    @Override
    public void testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        action.setRemoveCiphers(
                CipherSuite.TLS_AES_128_CCM_SHA256, CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA);
        super.testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject();
    }
}
