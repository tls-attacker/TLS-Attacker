/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import java.math.BigInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;

public class ChangeRsaParametersAction extends ConnectionBoundAction {
    private static final Logger LOGGER = LogManager.getLogger();
    private final BigInteger modulus, publicExponent, privateExponent;

    public ChangeRsaParametersAction(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        state.getTlsContext().setServerRSAModulus(modulus);
        state.getTlsContext().setServerRSAPublicKey(publicExponent);
        state.getTlsContext().setServerRSAPrivateKey(privateExponent);
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
