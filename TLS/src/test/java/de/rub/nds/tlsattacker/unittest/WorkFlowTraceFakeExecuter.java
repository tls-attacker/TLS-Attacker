/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.unittest;

import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkFlowTraceFakeExecuter {
    public static void execute(WorkflowTrace trace) {
	List<TLSAction> actionList = trace.getTLSActions();
	for (TLSAction action : actionList) {

	    if (action instanceof MessageAction) {
		MessageAction messageAction = (MessageAction) action;
		messageAction.getActualMessages().clear();
		messageAction.getActualMessages().addAll(messageAction.getConfiguredMessages());
	    }
	}
    }
}
