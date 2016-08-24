/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config.Analyzer;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class UniqueFlowsRuleConfig extends RuleConfig {

    public UniqueFlowsRuleConfig() {
	super("uniqueFlows/");
    }
}
