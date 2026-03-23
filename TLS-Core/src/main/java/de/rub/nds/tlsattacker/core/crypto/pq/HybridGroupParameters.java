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

public class HybridGroupParameters implements GroupParameters<Object> {
    private final GroupParameters<?> classicalParameters;
    private final GroupParameters<?> pqParameters;

    public HybridGroupParameters(
            GroupParameters<?> classicalParameters, GroupParameters<?> pqParameters) {
        this.classicalParameters = classicalParameters;
        this.pqParameters = pqParameters;
    }

    public HybridGroupParameters(
            GroupParameters<?> classicalParameters, MLKEMParameterSpec pqSpec) {
        this.classicalParameters = classicalParameters;
        this.pqParameters = new MLKEMGroupParameters(pqSpec);
    }

    public GroupParameters<?> getClassicalParameters() {
        return classicalParameters;
    }

    public GroupParameters<?> getPQParameters() {
        return pqParameters;
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
