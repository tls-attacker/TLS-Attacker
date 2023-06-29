/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ChangeCipherSuiteAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private CipherSuite newValue = null;
    private CipherSuite oldValue = null;

    public ChangeCipherSuiteAction(CipherSuite newValue) {
        // TODO can be better implemented with generics?
        super();
        this.newValue = newValue;
    }

    public ChangeCipherSuiteAction(String alias, CipherSuite newValue) {
        super(alias);
        this.newValue = newValue;
    }

    public ChangeCipherSuiteAction() {}

    public CipherSuite getNewValue() {
        return newValue;
    }

    public void setNewValue(CipherSuite newValue) {
        this.newValue = newValue;
    }

    public CipherSuite getOldValue() {
        return oldValue;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        oldValue = tlsContext.getSelectedCipherSuite();
        tlsContext.setSelectedCipherSuite(newValue);
        KeySet keySet;
        try {
            keySet = KeySetGenerator.generateKeySet(tlsContext);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
        tlsContext
                .getRecordLayer()
                .updateDecryptionCipher(
                        RecordCipherFactory.getRecordCipher(tlsContext, keySet, false));
        tlsContext
                .getRecordLayer()
                .updateEncryptionCipher(
                        RecordCipherFactory.getRecordCipher(tlsContext, keySet, true));
        LOGGER.info(
                "Changed CipherSuite from "
                        + (oldValue == null ? null : oldValue.name())
                        + " to "
                        + newValue.name());
        setExecuted(true);
    }

    @Override
    public void reset() {
        oldValue = null;
        setExecuted(null);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 17 * hash + Objects.hashCode(this.newValue);
        hash = 17 * hash + Objects.hashCode(this.oldValue);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ChangeCipherSuiteAction other = (ChangeCipherSuiteAction) obj;
        if (this.newValue != other.newValue) {
            return false;
        }
        return this.oldValue == other.oldValue;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
