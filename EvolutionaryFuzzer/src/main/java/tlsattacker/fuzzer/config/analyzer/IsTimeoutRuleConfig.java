/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.analyzer;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * A configuration class for the IsTimeoutRule
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class IsTimeoutRuleConfig extends RuleConfig {
    // The Timeout is not defined in the Timeout config, since the Timeout Rule
    // sees the WorkflowTrace first after it already Timedout

    /**
     *
     */
    
    public IsTimeoutRuleConfig() {
	super("timeout/");
    }
}
