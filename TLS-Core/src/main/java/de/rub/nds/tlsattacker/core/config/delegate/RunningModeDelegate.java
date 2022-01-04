/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;

public class RunningModeDelegate extends Delegate {

    @Parameter(names = "-running_mode", description = "The mode for which the workflow trace should be prepared")
    private RunningModeType runningMode = RunningModeType.CLIENT;

    public RunningModeDelegate() {
    }

    public RunningModeType getRunningMode() {
        return runningMode;
    }

    public void setRunningMode(RunningModeType runningMode) {
        this.runningMode = runningMode;
    }

    @Override
    public void applyDelegate(Config config) {
        config.setDefaultRunningMode(runningMode);
    }

}
