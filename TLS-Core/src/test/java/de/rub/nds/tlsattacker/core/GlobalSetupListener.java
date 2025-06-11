/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core;

import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestPlan;

public class GlobalSetupListener implements TestExecutionListener {
    private static final AtomicBoolean alreadyExecuted = new AtomicBoolean(false);

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        if (alreadyExecuted.compareAndSet(false, true)) {
            // Will be executed once for each fork
            ProviderUtil.addBouncyCastleProvider();
        }
    }
}
