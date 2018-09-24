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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.util.List;

/**
 *
 *
 */
public abstract class PaddingVectorGenerator {

    /**
     *
     */
    protected final PaddingRecordGenerator recordGenerator;

    /**
     *
     * @param type
     */
    public PaddingVectorGenerator(PaddingRecordGeneratorType type) {
        switch (type) {
            case LONG:
                recordGenerator = new LongRecordGenerator();
                break;
            case MEDIUM:
                recordGenerator = new MediumRecordGenerator();
                break;
            case SHORT:
                recordGenerator = new ShortRecordGenerator();
                break;
            case VERY_SHORT:
                recordGenerator = new VeryShortRecordGenerator();
                break;
            default:
                throw new IllegalArgumentException("Unknown RecordGenerator Type");
        }

    }

    /**
     *
     * @param config
     * @return
     */
    public abstract List<WorkflowTrace> getPaddingOracleVectors(Config config);

}
