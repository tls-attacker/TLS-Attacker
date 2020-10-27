/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.task;

import de.rub.nds.tlsattacker.core.exceptions.TransportHandlerConnectException;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TlsTask implements ITask, Callable<ITask> {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean hasError = false;

    private final int reexecutions;

    private final long additionalSleepTime;

    private final boolean increasingSleepTimes;

    private final long additionalTcpTimeout;

    public TlsTask(int reexecutions) {
        this.reexecutions = reexecutions;
        additionalSleepTime = 1000;
        increasingSleepTimes = true;
        this.additionalTcpTimeout = 5000;
    }

    public TlsTask(int reexecutions, long additionalSleepTime, boolean increasingSleepTimes, long additionalTcpTimeout) {
        this.reexecutions = reexecutions;
        this.additionalSleepTime = additionalSleepTime;
        this.increasingSleepTimes = increasingSleepTimes;
        this.additionalTcpTimeout = additionalTcpTimeout;
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
                boolean executionSuccess = execute();
                if (executionSuccess) {
                    hasError = false;
                    break;
                } else {
                    if (increasingSleepTimes) {
                        sleepTime += additionalSleepTime;
                    }
                    hasError = true;
                }
            } catch (TransportHandlerConnectException E) {
                LOGGER.warn("Could not connect to target. Sleep and Retry");
                try {
                    Thread.sleep(additionalTcpTimeout);
                } catch (InterruptedException ex) {
                    LOGGER.error("Interrupted during sleep", ex);
                }
                hasError = true;
                exception = E;
            } catch (Exception E) {
                LOGGER.error("Encountered an exception during the execution", E);
                hasError = true;
                if (increasingSleepTimes) {
                    sleepTime += additionalSleepTime;
                }
                exception = E;
            }
            if (i < reexecutions) {
                this.reset();
            }
        }
        if (hasError) {
            LOGGER.warn("Could not execute Workflow.", exception);
        }
        return this;
    }

    public boolean isHasError() {
        return hasError;
    }

    public abstract void reset();

    public int getReexecutions() {
        return reexecutions;
    }
}
