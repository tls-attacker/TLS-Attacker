/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 *
 */
public class ParallelExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExecutorService executorService;

    private final int size;

    private final int reexecutions;

    public ParallelExecutor(int size, int reexecutions) {
        executorService = new ThreadPoolExecutor(size, size, 10, TimeUnit.DAYS, new LinkedBlockingDeque<Runnable>());
        this.reexecutions = reexecutions;
        this.size = size;
        if (reexecutions < 0) {
            throw new IllegalArgumentException("Reexecutions is below zero");
        }
    }

    public ParallelExecutor(int size, int reexecutions, ThreadFactory factory) {
        executorService = new ThreadPoolExecutor(size, size, 10, TimeUnit.DAYS, new LinkedBlockingDeque<Runnable>(),
                factory);
        this.reexecutions = reexecutions;
        this.size = size;
        if (reexecutions < 0) {
            throw new IllegalArgumentException("Reexecutions is below zero");
        }
    }

    public Future addTask(TlsTask task) {
        if (executorService.isShutdown()) {
            throw new RuntimeException("Cannot add Tasks to already shutdown executor");
        }
        Future<?> submit = executorService.submit(task);
        return submit;
    }

    public Future addStateTask(State state) {
        return addTask(new StateExecutionTask(state, reexecutions));
    }

    public void bulkExecuteStateTasks(List<State> stateList) {
        List<Future> futureList = new LinkedList<>();
        for (State state : stateList) {
            futureList.add(addStateTask(state));
        }
        for (Future future : futureList) {
            try {
                future.get();
            } catch (InterruptedException | ExecutionException ex) {
                throw new RuntimeException("Failed to execute tasks!", ex);
            }
        }
    }

    public void bulkExecuteStateTasks(State... states) {
        this.bulkExecuteStateTasks(new ArrayList<>(Arrays.asList(states)));
    }

    public void bulkExecuteTasks(List<TlsTask> taskList) {
        List<Future> futureList = new LinkedList<>();
        for (TlsTask tlStask : taskList) {
            futureList.add(addTask(tlStask));
        }
        for (Future future : futureList) {
            try {
                future.get();
            } catch (InterruptedException | ExecutionException ex) {
                throw new RuntimeException("Failed to execute tasks!", ex);
            }
        }
    }

    public void bulkExecuteTasks(TlsTask... tasks) {
        this.bulkExecuteTasks(new ArrayList<>(Arrays.asList(tasks)));
    }

    public int getSize() {
        return size;
    }

    public void shutdown() {
        executorService.shutdown();
    }

    public int getReexecutions() {
        return reexecutions;
    }
}
