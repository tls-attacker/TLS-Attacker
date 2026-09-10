/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.task;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.exceptions.StarttlsNotSupportedException;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

public class TlsTaskTest {

    private static final int REEXECUTIONS = 3;

    /**
     * Counts executions of a task that always throws, to tell a retried failure apart from a
     * terminal one.
     */
    private static class ThrowingTask extends TlsTask {

        private final Supplier<RuntimeException> exceptionSupplier;

        private int executions = 0;

        public ThrowingTask(Supplier<RuntimeException> exceptionSupplier) {
            super(REEXECUTIONS, 0, false, 0);
            this.exceptionSupplier = exceptionSupplier;
        }

        @Override
        public boolean execute() {
            executions++;
            throw exceptionSupplier.get();
        }

        @Override
        public void reset() {}

        public int getExecutions() {
            return executions;
        }
    }

    /** The refusal must be reported as an error even though it is not retried. */
    @Test
    public void testStarttlsNotSupportedIsNotReexecuted() {
        ThrowingTask task = new ThrowingTask(() -> new StarttlsNotSupportedException("refused"));

        task.call();

        assertEquals(1, task.getExecutions());
        assertTrue(task.isHasError());
    }

    /** Any other failure may be transient, so the existing retry behavior must be preserved. */
    @Test
    public void testGenericExceptionIsReexecuted() {
        ThrowingTask task = new ThrowingTask(() -> new RuntimeException("transient"));

        task.call();

        assertEquals(REEXECUTIONS + 1, task.getExecutions());
        assertTrue(task.isHasError());
    }

    /** A task that succeeds runs once and reports no error. */
    @Test
    public void testSuccessfulTaskIsNotReexecuted() {
        TlsTask task =
                new TlsTask(REEXECUTIONS, 0, false, 0) {
                    @Override
                    public boolean execute() {
                        return true;
                    }

                    @Override
                    public void reset() {}
                };

        task.call();

        assertFalse(task.isHasError());
    }
}
