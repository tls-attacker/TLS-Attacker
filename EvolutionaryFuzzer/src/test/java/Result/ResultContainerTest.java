/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Result;

import Graphs.BranchTrace;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.util.ArrayList;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ResultContainerTest {

    public ResultContainerTest() {
    }

    /**
     * Test of getInstance method, of class ResultContainer.
     */
    @Test
    public void testGetInstance() {
	ResultContainer result = ResultContainer.getInstance();
	assertNotNull(result);
    }

    /**
     * Test of commit method, of class ResultContainer.
     */
    @Test
    public void testCommit() {

	Result result = new Result(true, true, 0, System.currentTimeMillis(), new BranchTrace(), new WorkflowTrace(),
		new WorkflowTrace(), "test.unit");
	ResultContainer instance = ResultContainer.getInstance();
	instance.commit(result);

    }
}
