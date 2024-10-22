/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.SuppressingFalseBooleanAdapter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeyDerivator;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "ChangePreMasterSecret")
public class ChangePreMasterSecretAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] newValue = null;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] oldValue = null;

    @XmlJavaTypeAdapter(SuppressingFalseBooleanAdapter.class)
    private boolean updateMasterSecret = false;

    @XmlTransient private boolean asPlanned = false;

    public ChangePreMasterSecretAction(byte[] newValue) {
        super();
        this.newValue = newValue;
    }

    public ChangePreMasterSecretAction(byte[] newValue, boolean updateMasterSecret) {
        super();
        this.newValue = newValue;
        this.updateMasterSecret = updateMasterSecret;
    }

    public ChangePreMasterSecretAction() {}

    public void setNewValue(byte[] newValue) {
        this.newValue = newValue;
    }

    public byte[] getNewValue() {
        return newValue;
    }

    public byte[] getOldValue() {
        return oldValue;
    }

    public boolean isUpdateMasterSecret() {
        return updateMasterSecret;
    }

    public void setUpdateMasterSecret(boolean updateMasterSecret) {
        this.updateMasterSecret = updateMasterSecret;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        oldValue = tlsContext.getPreMasterSecret();
        tlsContext.setPreMasterSecret(newValue);
        LOGGER.info("Changed PreMasterSecret from {} to {}", oldValue, newValue);
        asPlanned = true;
        if (updateMasterSecret) {
            byte[] clientServerRandom =
                    ArrayConverter.concatenate(
                            tlsContext.getChooser().getClientRandom(),
                            tlsContext.getChooser().getServerRandom());
            try {
                byte[] newMasterSecret =
                        KeyDerivator.calculateMasterSecret(tlsContext, clientServerRandom);
                LOGGER.info(
                        "Derived new master secret {} using clientServerRandom {}",
                        newMasterSecret,
                        clientServerRandom);
                tlsContext.setMasterSecret(newMasterSecret);
            } catch (CryptoException e) {
                asPlanned = false;
                LOGGER.error("Could not update master secret: {}", e);
            }
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
        oldValue = null;
        setExecuted(null);
        asPlanned = false;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 19 * hash + Arrays.hashCode(this.newValue);
        hash = 19 * hash + Arrays.hashCode(this.oldValue);
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
        final ChangePreMasterSecretAction other = (ChangePreMasterSecretAction) obj;
        if (!Arrays.equals(this.newValue, other.newValue)) {
            return false;
        }
        return Arrays.equals(this.oldValue, other.oldValue);
    }

    @Override
    public boolean executedAsPlanned() {
        return asPlanned;
    }
}
