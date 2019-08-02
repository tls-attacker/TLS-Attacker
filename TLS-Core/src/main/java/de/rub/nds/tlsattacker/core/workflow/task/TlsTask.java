/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
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
                execute();
                hasError = false;
                break;
            } catch (TransportHandlerConnectException E) {
                LOGGER.warn("Could not connect to target. Sleep and Retry");
                try {
                    Thread.sleep(additionalTcpTimeout);
                } catch (InterruptedException ex) {
                    LOGGER.error("Interrupted during sleep", E);
                }
                hasError = true;
                exception = E;
            } catch (Exception E) {
                LOGGER.warn("Encountered an exception during the execution", E);
                hasError = true;
                if (increasingSleepTimes) {
                    sleepTime += additionalSleepTime;
                }
                exception = E;
            }
            this.reset();
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
