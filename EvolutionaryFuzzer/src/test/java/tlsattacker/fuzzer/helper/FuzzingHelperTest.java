/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.helper;

import tlsattacker.fuzzer.helper.FuzzingHelper;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzingHelperTest {

    /**
     *
     */
    public FuzzingHelperTest() {
    }

    /**
     * Test of pickRandomField method, of class FuzzingHelper.
     */
    @Test
    public void testPickRandomField() {
	List<ModifiableVariableField> fields = new ArrayList<>();
	fields.add(new ModifiableVariableField());
	fields.add(new ModifiableVariableField());
	fields.add(new ModifiableVariableField());
	ModifiableVariableField result = FuzzingHelper.pickRandomField(fields);
	assertNotNull("Failure: Should return a Field", result);
    }

    /**
     * Test of getModifiableVariableHolders method, of class FuzzingHelper.
     */
    @Test
    public void testGetModifiableVariableHolders() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new ClientHelloMessage()));
	List<ModifiableVariableHolder> result = FuzzingHelper.getModifiableVariableHolders(trace);
	assertTrue("Failure: WorkflowTrace should contain atleast one Holder", result.size() > 0);
    }

    /**
     * Test of addRecordAtRandom method, of class FuzzingHelper.
     */
    @Test
    public void testAddRecordsAtRandom() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new ClientHelloMessage()));
	FuzzingHelper.addRecordAtRandom(trace);
    }

    /**
     * Test of removeRandomMessage method, of class FuzzingHelper.
     */
    @Test
    public void testRemoveRandomMessage() {
	WorkflowTrace tempTrace = new WorkflowTrace();
	tempTrace.add(new SendAction(new ClientHelloMessage()));
	tempTrace.add(new ReceiveAction(new ServerHelloMessage()));

	FuzzingHelper.removeRandomMessage(tempTrace);
	assertTrue(
		"Failure: Workflow should contain only two Messages after. Since both Actions only contain one message",
		tempTrace.getAllConfiguredMessages().size() == 2);
	tempTrace = new WorkflowTrace();
	List<ProtocolMessage> messages = new LinkedList<>();
	messages.add(new AlertMessage());
	messages.add(new AlertMessage());
	tempTrace.add(new SendAction(messages));
	assertTrue("Failure: Workflow should contain two Messages", tempTrace.getAllConfiguredMessages().size() == 2);
	FuzzingHelper.removeRandomMessage(tempTrace);
	assertTrue("Failure: Workflow should contain only one Message after.", tempTrace.getAllConfiguredMessages()
		.size() == 1);

    }

    /**
     * Test of addRandomMessage method, of class FuzzingHelper.
     */
    @Test
    public void testAddRandomMessage() {
	WorkflowTrace tempTrace = new WorkflowTrace();
	FuzzingHelper.addMessageFlight(tempTrace);
	FuzzingHelper.addRandomMessage(tempTrace);
	assertTrue(
		"A Workflowtrace should contain 3 Messages after we added one at Random. (The arbitary Message for the Server is always added + random message from flight)",
		tempTrace.getAllConfiguredMessages().size() == 3);
    }

    /**
     * Test of duplicateRandomProtocolMessage method, of class FuzzingHelper.
     */
    @Test
    public void testDuplicateRandomProtocolMessage() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new ClientHelloMessage()));

	FuzzingHelper.duplicateRandomProtocolMessage(trace);
	assertTrue("Failure: After Duplicating the Trace should contain 2 Messages", trace.getAllConfiguredMessages()
		.size() == 2);
    }

    /**
     * Test of getAllModifiableVariableHoldersRecursively method, of class
     * FuzzingHelper.
     */
    @Test
    public void testGetAllModifiableVariableHoldersRecursively() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new ClientHelloMessage()));

	int size = FuzzingHelper.getAllModifiableVariableFieldsRecursively(trace).size();
	assertTrue("Failure: Trace should contain more than zero Holders", size > 0);
    }

}
