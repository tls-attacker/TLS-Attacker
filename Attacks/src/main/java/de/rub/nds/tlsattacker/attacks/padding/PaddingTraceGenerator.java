/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

/**
 *
 *
 */
public abstract class PaddingTraceGenerator {

    /**
     *
     */
    protected final PaddingVectorGenerator vectorGenerator;

    /**
     *
     * @param type
     */
    public PaddingTraceGenerator(PaddingRecordGeneratorType type) {
        switch (type) {
            case LONG:
                vectorGenerator = new LongPaddingGenerator();
                break;
            case MEDIUM:
                vectorGenerator = new MediumPaddingGenerator();
                break;
            case SHORT:
                vectorGenerator = new ShortPaddingGenerator();
                break;
            case VERY_SHORT:
                vectorGenerator = new VeryShortPaddingGenerator();
                break;
            default:
                throw new IllegalArgumentException("Unknown RecordGenerator Type");
        }

    }

    /**
     *
     * @param config
     * @param vector
     * @return
     */
    public abstract WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector);

    public PaddingVectorGenerator getVectorGenerator() {
        return vectorGenerator;
    }
}
