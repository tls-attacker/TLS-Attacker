/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import java.math.BigInteger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeRsaParametersAction extends ConnectionBoundAction {
    private static final Logger LOGGER = LogManager.getLogger();
    private final BigInteger N, e, d;

    public ChangeRsaParametersAction(BigInteger N, BigInteger e, BigInteger d) {
        this.N = N;
        this.e = e;
        this.d = d;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        state.getTlsContext().setServerRsaModulus(N);
        state.getTlsContext().setServerRSAPublicKey(e);
        state.getTlsContext().setServerRSAPrivateKey(d);
        setExecuted(true);
        LOGGER.info("Changed N,e,d");
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
