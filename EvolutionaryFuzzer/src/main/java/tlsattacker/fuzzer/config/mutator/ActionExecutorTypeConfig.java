/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.mutator;

import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.Serializable;
import java.util.Random;

/**
 * The configuration file for the ActionExecutors used while fuzzing
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ActionExecutorTypeConfig implements Serializable {

    /**
     *
     */
    private boolean allowTLS = true;

    /**
     *
     */
    private boolean allowDTLS = false;

    /**
     *
     */
    public ActionExecutorTypeConfig() {
    }

    /**
     *
     * @return
     */
    public boolean isAllowTLS() {
	return allowTLS;
    }

    /**
     *
     * @param allowTLS
     */
    public void setAllowTLS(boolean allowTLS) {
	this.allowTLS = allowTLS;
    }

    /**
     *
     * @return
     */
    public boolean isAllowDTLS() {
	return allowDTLS;
    }

    /**
     *
     * @param allowDTLS
     */
    public void setAllowDTLS(boolean allowDTLS) {
	this.allowDTLS = allowDTLS;
    }

    /**
     *
     * @return
     */
    public ExecutorType getRandomExecutorType() {
	if (!allowDTLS && !allowTLS) {
	    throw new ConfigurationException(
		    "TLSActionExecutor and DTLSActionExecutor are disabled, allow atleast one!");
	} else if (allowDTLS && !allowTLS) {
	    return ExecutorType.DTLS;
	} else if (!allowDTLS && allowTLS) {
	    return ExecutorType.TLS;
	} else {
	    Random r = new Random();
	    return r.nextBoolean() ? ExecutorType.DTLS : ExecutorType.TLS;
	}

    }
}
