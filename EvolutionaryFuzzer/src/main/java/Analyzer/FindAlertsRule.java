/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.EarlyHeartbeatRuleConfig;
import Config.Analyzer.FindAlertsRuleConfig;
import Config.Analyzer.UniqueFlowsRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Result.Result;
import TestVector.TestVector;
import TestVector.TestVectorSerializer;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FindAlertsRule extends Rule {

    private int found = 0;
    private boolean[] alertMap = new boolean[Byte.MAX_VALUE];
    private FindAlertsRuleConfig config;

    public FindAlertsRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "find_alerts.rule");
	File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
	if (f.exists()) {
	    config = JAXB.unmarshal(f, FindAlertsRuleConfig.class);
	}
	if (config == null) {
	    config = new FindAlertsRuleConfig();
	    writeConfig(config);
	}
	prepareConfigOutputFolder();
	if (config.isSaveOneOfEach()) {
	    // Load previously seen Testvectors and scan them for seen alert
	    // messages
	    f = new File(evoConfig.getOutputFolder() + this.getConfig().getOutputFolder());
	    List<TestVector> vectorList = TestVectorSerializer.readFolder(f);
	    for (TestVector vector : vectorList) {
		List<Integer> positions = vector.getTrace().getProtocolMessagePositions(ProtocolMessageType.ALERT);
		for (Integer i : positions) {
		    AlertMessage pm = (AlertMessage) vector.getTrace().getProtocolMessages().get(i);
		    alertMap[pm.getDescription().getOriginalValue().byteValue()] = true;
		}
	    }
	}
    }

    @Override
    public boolean applys(Result result) {
	WorkflowTrace trace = result.getExecutedVector().getTrace();
	if (trace.containsProtocolMessage(ProtocolMessageType.ALERT)) {
	    List<Integer> positions = trace.getProtocolMessagePositions(ProtocolMessageType.ALERT);
	    for (Integer i : positions) {
		AlertMessage pm = (AlertMessage) trace.getProtocolMessages().get(i);
		if (pm.getMessageIssuer() == ConnectionEnd.SERVER) {
		    // If Message is in blacklist it applys
		    if (config.getBlacklist().contains(pm.getDescription().getOriginalValue().byteValue())) {
			return true;
		    }
		    // If Message is not in Whitelist
		    if (!config.getWhitelist().contains(pm.getDescription().getOriginalValue().byteValue())) {
			return true;
		    }
		    if (config.isSaveOneOfEach() && !alertMap[pm.getDescription().getOriginalValue().byteValue()]) {
			return true;
		    }
		}
	    }
	}
	return false;

    }

    @Override
    public void onApply(Result result) {
	WorkflowTrace trace = result.getExecutedVector().getTrace();
	List<Integer> positions = trace.getProtocolMessagePositions(ProtocolMessageType.ALERT);
	StringBuilder containsAlerts = new StringBuilder("");
	if (config.isSaveOneOfEach()) {
	    for (Integer i : positions) {
		AlertMessage pm = (AlertMessage) trace.getProtocolMessages().get(i);
		if (!alertMap[pm.getDescription().getOriginalValue()]) {
		    containsAlerts.append("," + pm.getDescription().getOriginalValue());
		}
		alertMap[pm.getDescription().getOriginalValue().byteValue()] = true;
	    }
	}
	found++;
	File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
	try {
	    result.getExecutedVector()
		    .getTrace()
		    .setDescription("WorkflowTrace contains interesting Alert Messages, in specially:" + containsAlerts);
	    TestVectorSerializer.write(f, result.getExecutedVector());
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

	StringBuilder builder = new StringBuilder("Alerts found:" + found + "\n");
	for (int i = 0; i < Byte.MAX_VALUE; i++) {
	    if (alertMap[i]) {
		try {
		    AlertDescription desc = AlertDescription.getAlertDescription((byte) i);
		    if (desc != null) {
			builder.append(desc.toString()).append("\n");
			;
		    } else {
			builder.append(i).append("\n");

		    }
		} catch (Exception E) {
		    builder.append(i).append("n");
		}
	    }
	}
	builder.append("\n");
	return builder.toString();

    }

    @Override
    public FindAlertsRuleConfig getConfig() {
	return config;
    }

    private static final Logger LOG = Logger.getLogger(FindAlertsRule.class.getName());

}
