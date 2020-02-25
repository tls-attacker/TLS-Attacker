/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class SpecialDrownCommandConfig extends BaseDrownCommandConfig {

    private enum OracleType {
        EXTRA_CLEAR,
        LEAKY_EXPORT
    }

    public static final String COMMAND = "specialDrown";

    @Parameter(names = "-oracleType", description = "The oracle to use, i.e. the "
            + "variant of Special DROWN to be executed", required = true)
    private OracleType oracleType = OracleType.EXTRA_CLEAR;
    @Parameter(names = "-checkDataFile", description = "Path of the state file for "
            + "'leaky export' oracle vulnerability check")
    private String checkDataFilePath;
    @Parameter(names = "-genCheckData", description = "Generate state file for 'leaky export' vulnerability check")
    private boolean genCheckData;
    @Parameter(names = "-analyzeCheckData", description = "Analyze given state file for "
            + "'leaky export' oracle vulnerability check, this might take a long time")
    private boolean analyzeCheckData;

    public SpecialDrownCommandConfig(GeneralDelegate delegate) {
        super(delegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();

        // The DROWN paper doesn't explicitly state that the "extra clear"
        // oracle doesn't work on export ciphers, but I couldn't get it working
        if (oracleType == OracleType.EXTRA_CLEAR && config.getDefaultSSL2CipherSuite().isExport()) {
            throw new ConfigurationException("'Extra clear' oracle requires a non-export cipher");
        }
        // TODO: Check cipher suite for Leaky Export

        return config;
    }

    @Override
    public boolean isSkipConnectionCheck() {
        return super.isSkipConnectionCheck() || isAnalyzeCheckData();
    }

    public boolean isExtraClearOracleEnabled() {
        return oracleType == OracleType.EXTRA_CLEAR;
    }

    public boolean isLeakyExportOracleEnabled() {
        return oracleType == OracleType.LEAKY_EXPORT;
    }

    public String getCheckDataFilePath() {
        return checkDataFilePath;
    }

    public boolean isGenCheckData() {
        return genCheckData;
    }

    public boolean isAnalyzeCheckData() {
        return analyzeCheckData;
    }

}
