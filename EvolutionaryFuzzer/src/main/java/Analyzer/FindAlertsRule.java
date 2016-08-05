/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.EvolutionaryFuzzerConfig;
import Result.Result;
import Result.ResultContainer;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FindAlertsRule extends Rule {

    private EvolutionaryFuzzerConfig evoConfig;
    private int found = 0;

    public FindAlertsRule(EvolutionaryFuzzerConfig evoConfig) {
	this.evoConfig = evoConfig;
    }

    @Override
    public boolean applys(Result result) {
	WorkflowTrace trace = result.getVector().getTrace();
	if (trace.containsProtocolMessage(ProtocolMessageType.ALERT)) {
	    List<Integer> positions = trace.getProtocolMessagePositions(ProtocolMessageType.ALERT);
	    for (Integer i : positions) {
		AlertMessage pm = (AlertMessage) trace.getProtocolMessages().get(i);
		if (pm.getDescription().getOriginalValue().byteValue() == (byte) 80) {
		    return true;
		}
	    }
	}
	return false;

    }

    @Override
    public void onApply(Result result) {
	found++;
	File f = new File(evoConfig.getOutputFolder() + "interesting/" + result.getId());
	try {
	    result.getExecutedVector().getTrace().setDescription("WorkflowTrace contains InternalError Alert Message");
	    f.createNewFile();
	    WorkflowTraceSerializer.write(f, result.getExecutedVector().getTrace());
	} catch (JAXBException | IOException E) {
	    LOG.log(Level.SEVERE,
		    "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
			    + f.getAbsolutePath(), E);
	}

    }

    @Override
    public void onDecline(Result result) {
    }

    @Override
    public String report() {
	if (found > 0) {
	    return "Found " + found + " Traces which returned an Internal Error Alert Message.\n";
	} else {
	    return null;
	}
    }

    private static final Logger LOG = Logger.getLogger(FindAlertsRule.class.getName());

}
