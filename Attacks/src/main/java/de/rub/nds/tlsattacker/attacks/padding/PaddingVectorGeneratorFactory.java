/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;

/**
 *
 * @author robert
 */
public class PaddingVectorGeneratorFactory {

    /**
     *
     * @param config
     * @return
     */
    public static PaddingVectorGenerator getPaddingVectorGenerator(PaddingOracleCommandConfig config) {
        switch (config.getVectorGeneratorType()) {
            case CLASSIC:
                return new ClassicPaddingGenerator(config.getRecordGeneratorType());
            case FINISHED:
                return new FinishedPaddingGenerator(config.getRecordGeneratorType());
            case FINISHED_RESUMPTION:
                return new FinishedResumptionPaddingGenerator(config.getRecordGeneratorType());
            case CLOSE_NOTIFY:
                return new ClassicCloseNotifyVectorGenerator(config.getRecordGeneratorType());
            case CLASSIC_DYNAMIC:
                return new ClassicDynamicPaddingGenerator(config.getRecordGeneratorType());
            default:
                throw new IllegalArgumentException("Unknown PaddingVectorGenerator: " + config.getVectorGeneratorType());
        }
    }

    private PaddingVectorGeneratorFactory() {
    }
}
