/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Result.Result;
import java.io.File;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Rule {
    protected File ruleFolder;

    public File getRuleFolder() {
	return ruleFolder;
    }

    public abstract boolean applys(Result result);

    public abstract void onApply(Result result);

    public abstract void onDecline(Result result);

    public abstract String report();
}
