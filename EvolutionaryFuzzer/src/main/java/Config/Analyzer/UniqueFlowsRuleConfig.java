/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config.Analyzer;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class UniqueFlowsRuleConfig extends RuleConfig {
    private String outputFolder = "uniqueFlows/";

    public String getOutputFolder() {
	return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
	this.outputFolder = outputFolder;
    }

}
