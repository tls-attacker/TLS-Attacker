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
 *
 */
public class PaddingTraceGeneratorFactory {

    /**
     *
     * @param config
     * @return
     */
    public static PaddingTraceGenerator getPaddingTraceGenerator(PaddingOracleCommandConfig config) {
        switch (config.getVectorGeneratorType()) {
            case CLASSIC:
                return new ClassicPaddingTraceGenerator(config.getRecordGeneratorType());
            case FINISHED:
                return new FinishedPaddingTraceGenerator(config.getRecordGeneratorType());
            case FINISHED_RESUMPTION:
                return new FinishedResumptionPaddingTraceGenerator(config.getRecordGeneratorType());
            case CLOSE_NOTIFY:
                return new ClassicCloseNotifyTraceGenerator(config.getRecordGeneratorType());
            case CLASSIC_DYNAMIC:
                return new ClassicDynamicPaddingTraceGenerator(config.getRecordGeneratorType());
            default:
                throw new IllegalArgumentException("Unknown PaddingTraceGenerator: " + config.getVectorGeneratorType());
        }
    }

    private PaddingTraceGeneratorFactory() {
    }
}
