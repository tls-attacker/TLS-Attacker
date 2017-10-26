/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.filter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

/**
 * Filters workflow trace data for output.
 * 
 * Usually used to clean up workflow traces before serialization.
 * 
 * Note that filtering is unidirectional, i.e. we cannot guarantee that a
 * filtered workflow trace can be loaded to a normalized workflow again.
 * 
 * <p>
 * TODO: When this class grows, consider giving the user access to it via
 * command line. Something like
 * <code>TLS-Utils -filter filtername -input trace.xml -output filtered.xml</code>
 * Once that utility exists, one could consider allowing only those filters in
 * TLS-{Client,Server,Mitm} that can be reversed, (or no filters at all). So
 * that the following always works as expected: <code>
 * TLS-Client -connect localhost:443 -workflow_output trace.xml
 * TLS-Client -connect localhost:443 -workflow_input trace.xml
 * </code>
 * </p>
 */
public abstract class Filter {

    protected final Config config;

    public Filter(Config config) {
        this.config = config;
    }

    public abstract WorkflowTrace filteredCopy(WorkflowTrace trace, Config config);

}
