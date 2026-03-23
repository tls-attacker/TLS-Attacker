/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.pq;

import de.rub.nds.protocol.constants.GroupParameters;
import de.rub.nds.protocol.crypto.CyclicGroup;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

public class MLKEMGroupParameters implements GroupParameters<Object> {

    private final MLKEMParameterSpec parameterSpec;

    public MLKEMGroupParameters(MLKEMParameterSpec parameterSpec) {
        this.parameterSpec = parameterSpec;
    }

    public MLKEMParameterSpec getParameterSpec() {
        return parameterSpec;
    }

    @Override
    public int getElementSizeBits() {
        return 0; // TODO: ???
    }

    @Override
    public int getElementSizeBytes() {
        return 0; // TODO: ???
    }

    @Override
    public CyclicGroup<Object> getGroup() {
        return null;
    }
}
