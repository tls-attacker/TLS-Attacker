/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.task;

import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TlsTask implements ITask, Callable<ITask> {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean hasError = false;

    private final int reexecutions;

    private final long additionalSleepTime;

    private final boolean increasingSleepTimes;

    public TlsTask(int reexecutions) {
        this.reexecutions = reexecutions;
        additionalSleepTime = 1000;
        increasingSleepTimes = true;
    }

    public TlsTask(int reexecutions, long additionalSleepTime, boolean increasingSleepTimes) {
        this.reexecutions = reexecutions;
        this.additionalSleepTime = additionalSleepTime;
        this.increasingSleepTimes = increasingSleepTimes;
    }

    @Override
    public ITask call() {
        Exception exception = null;
        long sleepTime = 0;
        for (int i = 0; i < reexecutions + 1; i++) {
            try {
                if (sleepTime > 0) {
                    Thread.sleep(sleepTime);
                }
                execute();
                hasError = false;
                break;
            } catch (Exception E) {
                LOGGER.debug("Encountered an exception during the execution", E);
                hasError = true;
                if (increasingSleepTimes) {
                    sleepTime += additionalSleepTime;
                }
                exception = E;
            }
        }
        if (hasError) {
            LOGGER.error("Could not execute Workflow.", exception);
        }
        return this;
    }

    public boolean isHasError() {
        return hasError;
    }

    public abstract void reset();
}
