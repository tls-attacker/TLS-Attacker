/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package WorkFlowType;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import java.util.ArrayList;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowTraceType {

    private ArrayList<MessageFlow> flows;

    public ArrayList<MessageFlow> getFlows()
    {
        return flows;
    }

    public WorkflowTraceType() {
	flows = new ArrayList<>();
    }

    public void addMessageFlow(MessageFlow flow) {
	flows.add(flow);
    }

    @Override
    public int hashCode() {
	int hash = 7;
	return hash;
    }

    @Override
    public boolean equals(Object obj) {
	if (obj == null) {
	    return false;
	}
	if (getClass() != obj.getClass()) {
	    return false;
	}
	final WorkflowTraceType other = (WorkflowTraceType) obj;
	if (flows.size() != other.flows.size()) {
	    return false;
	}
	for (int i = 0; i < flows.size(); i++) {
	    if (!flows.get(i).equals(other.flows.get(i))) {
		return false;
	    }
	}
	return true;
    }

    public void clean() {
	for (int i = flows.size() - 1; i >= 0; i--) {
	    MessageFlow flow = flows.get(i);
	    if (flow.getIssuer() == ConnectionEnd.CLIENT) {
		flows.remove(i);
	    } else {
		break;
	    }
	}
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder("WorkflowTraceType:\n");
	for (MessageFlow flow : flows) {
	    sb.append(flow.toString() + "\n");
	}
	return sb.toString();
    }

}
