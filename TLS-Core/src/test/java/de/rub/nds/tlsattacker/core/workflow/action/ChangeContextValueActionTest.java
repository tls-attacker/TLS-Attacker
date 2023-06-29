/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class ChangeContextValueActionTest
        extends AbstractChangeActionTest<ChangeContextValueAction<ProtocolVersion>> {

    @SuppressWarnings("unchecked")
    public ChangeContextValueActionTest() {
        super(
                new ChangeContextValueAction<>("selectedProtocolVersion", ProtocolVersion.SSL2),
                (Class<ChangeContextValueAction<ProtocolVersion>>)
                        (Class<?>) ChangeContextValueAction.class);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testException1() {
        ChangeContextValueAction<ProtocolVersion> b =
                (ChangeContextValueAction<ProtocolVersion>) trace.getTlsActions().get(0);
        assertThrows(UnsupportedOperationException.class, b::getNewValueList);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testException2() {
        trace.addTlsAction(
                new ChangeContextValueAction<>(
                        "", CipherSuite.GREASE_00, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256));
        ChangeContextValueAction<CipherSuite> b =
                (ChangeContextValueAction<CipherSuite>) trace.getTlsActions().get(1);
        assertThrows(UnsupportedOperationException.class, b::getNewValue);
    }

    /** Test of setNewValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testSetNewValue() {
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
        action.setNewValue(ProtocolVersion.TLS11);
        assertEquals(action.getNewValue(), ProtocolVersion.TLS11);
    }

    /** Test of getNewValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testGetNewValue() {
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
    }

    /** Test of getOldValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testGetOldValue() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        action.execute(state);
        assertEquals(action.getOldValue(), ProtocolVersion.TLS12);
    }

    /** Test of execute method, of class ChangeCompressionAction. */
    @Test
    public void testExecute() throws Exception {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        super.testExecute();
        assertEquals(action.getOldValue(), ProtocolVersion.TLS12);
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
        assertEquals(context.getSelectedProtocolVersion(), ProtocolVersion.SSL2);
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    @Override
    public void testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        List<CipherSuite> ls =
                List.of(
                        CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);

        ChangeContextValueAction<byte[]> action2 =
                new ChangeContextValueAction<>("handshakeSecret", new byte[] {0x01, 0x02, 0x03});
        ChangeContextValueAction<CipherSuite> action3 =
                new ChangeContextValueAction<>("clientSupportedCipherSuites", ls);
        ChangeContextValueAction<PRFAlgorithm> action4 =
                new ChangeContextValueAction<>("prfAlgorithm", PRFAlgorithm.TLS_PRF_SHA256);

        trace.addTlsActions(action2);
        trace.addTlsActions(action3);
        trace.addTlsActions(action4);
        WorkflowTrace copy = state.getWorkflowTraceCopy();

        assertEquals(action, copy.getTlsActions().get(0));
        assertEquals(action2, copy.getTlsActions().get(1));
        assertEquals(action3, copy.getTlsActions().get(2));
        assertEquals(action4, copy.getTlsActions().get(3));
    }
}
