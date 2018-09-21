/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class PrintLastHandledApplicationDataActionTest {

    private State state;
    private TlsContext ctx;
    private PrintLastHandledApplicationDataAction action;
    private final String expectedAppDataEncodedString = "GET /theTestData";
    private final String expectedAppDataHexString = "\n47 45 54 20 2F 74 68 65  54 65 73 74 44 61 74 61";

    public PrintLastHandledApplicationDataActionTest() {
    }

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        action = new PrintLastHandledApplicationDataAction();

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(trace);

        ctx = state.getTlsContext();
        ctx.setLastHandledApplicationMessageData(expectedAppDataEncodedString.getBytes());
    }

    @Test
    public void executingWithDefaultsSavesHex() throws IOException {
        action.execute(state);
        assertThat(action.getLastHandledApplicationData(), equalTo(expectedAppDataHexString));
        assertTrue(action.executedAsPlanned());
        assertTrue(action.isExecuted());
    }

    @Test
    public void executingWithAsciiEncodingSavesAscii() throws IOException {
        action.setStringEncoding("US-ASCII");
        action.execute(state);
        assertThat(action.getLastHandledApplicationData(), equalTo(expectedAppDataEncodedString));
        assertTrue(action.executedAsPlanned());
        assertTrue(action.isExecuted());
    }

    @Test
    public void testReset() throws IOException {
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingEmptyActionYieldsMinimalOutput() {
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(SendAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(SendAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        action.setStringEncoding("US-ASCII");
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }

}
