/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rules;

import tlsattacker.fuzzer.config.analyzer.FindAlertsRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVector;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.IOException;
import java.util.List;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;

/**
 * A rule which records the different observed alert descriptions and records
 * unusual alerts.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FindAlertsRule extends Rule {

    /**
     * The number of TestVectors that this rule applied to
     */
    private int found = 0;

    /**
     * An boolean array which contains a flag for every received alert code
     */
    private final boolean[] alertMap = new boolean[Byte.MAX_VALUE];

    /**
     * The configuration object for this rule
     */
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
                List<ProtocolMessage> messages = vector.getTrace().getActuallyRecievedProtocolMessagesOfType(
                        ProtocolMessageType.ALERT);
                for (ProtocolMessage message : messages) {
                    AlertMessage pm = (AlertMessage) message;
                    alertMap[pm.getDescription().getOriginalValue().byteValue()] = true;
                }
            }
        }
    }

    /**
     * The rule applies if it contains either an alert description which is on
     * the Blacklist or Whitelist. The rule also applies if the saveOneOfEach
     * option is set, if the rule has never seen the alert description before
     * 
     * @param result
     *            AgentResult to analyze
     * @return
     */
    @Override
    public synchronized boolean applies(AgentResult result) {
        WorkflowTrace trace = result.getVector().getTrace();
        List<ProtocolMessage> messages = trace.getActualReceivedProtocolMessagesOfType(ProtocolMessageType.ALERT);
        if (!messages.isEmpty()) {
            for (ProtocolMessage message : messages) {
                AlertMessage pm = (AlertMessage) message;
                // If Message is in blacklist it applies
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
        return false;

    }

    /**
     * Stores the TestVector
     * 
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public synchronized void onApply(AgentResult result) {
        WorkflowTrace trace = result.getVector().getTrace();
        List<ProtocolMessage> messages = trace.getActualReceivedProtocolMessagesOfType(ProtocolMessageType.ALERT);
        StringBuilder containsAlerts = new StringBuilder("");
        if (config.isSaveOneOfEach()) {
            for (ProtocolMessage message : messages) {
                AlertMessage pm = (AlertMessage) message;
                if (!alertMap[pm.getDescription().getOriginalValue()]) {
                    containsAlerts.append(",").append(pm.getDescription().getOriginalValue());
                }
                alertMap[pm.getDescription().getOriginalValue().byteValue()] = true;
            }
        }
        found++;
        File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
        try {
            result.getVector()
                    .getTrace()
                    .setDescription("WorkflowTrace contains interesting Alert Messages, in specially:" + containsAlerts);
            TestVectorSerializer.write(f, result.getVector());
        } catch (JAXBException | IOException E) {
            LOGGER.error(
                    "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
                            + f.getAbsolutePath(), E);
        }

    }

    /**
     * Do nothing
     * 
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public void onDecline(AgentResult result) {
    }

    /**
     * Generates a status report
     * 
     * @return
     */
    @Override
    public synchronized String report() {

        StringBuilder builder = new StringBuilder("Alerts found:" + found + "\n");
        for (int i = 0; i < Byte.MAX_VALUE; i++) {
            if (alertMap[i]) {
                try {
                    AlertDescription desc = AlertDescription.getAlertDescription((byte) i);
                    if (desc != null) {
                        builder.append(desc.toString()).append("\n");
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

}
