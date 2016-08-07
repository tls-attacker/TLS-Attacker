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
public class IsTimeoutRuleConfig extends RuleConfig {
    // The Timeout is not defined in the Timeout config, since the Timeout Rule
    // sees the WorkflowTrace first after it already Timedout
    private String outputFolder = "timeout/";

    public String getOutputFolder() {
	return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
	this.outputFolder = outputFolder;
    }

}
