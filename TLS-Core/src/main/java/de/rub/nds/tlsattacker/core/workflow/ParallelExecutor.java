/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

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

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.task.ITask;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;

/**
 *
 *
 */
public class ParallelExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExecutorService executorService;

    private final int size;

    private final int reexecutions;

    private ParallelExecutor(int size, int reexecutions, ExecutorService executorService) {
        this.executorService = executorService;
        this.reexecutions = reexecutions;
        this.size = size;
        if (reexecutions < 0) {
            throw new IllegalArgumentException("Reexecutions is below zero");
        }
    }

    public ParallelExecutor(ExecutorService executorService, int reexecutions) {
        this(-1, reexecutions, executorService);
    }

    public ParallelExecutor(int size, int reexecutions) {
        this(size, reexecutions,
                new ThreadPoolExecutor(size, size, 10, TimeUnit.DAYS, new LinkedBlockingDeque<Runnable>()));
    }

    public ParallelExecutor(int size, int reexecutions, ThreadFactory factory) {
        this(size, reexecutions,
                new ThreadPoolExecutor(size, size, 5, TimeUnit.MINUTES, new LinkedBlockingDeque<Runnable>(), factory));
    }

    public Future<ITask> addTask(TlsTask task) {
        if (executorService.isShutdown()) {
            throw new RuntimeException("Cannot add Tasks to already shutdown executor");
        }
        return executorService.submit(task);
    }

    public Future<ITask> addStateTask(State state) {
        return addTask(new StateExecutionTask(state, reexecutions));
    }

    public List<ITask> bulkExecuteStateTasks(List<State> stateList) {
        List<TlsTask> tasks = new ArrayList<>(stateList.size());
        for (State s : stateList) {
            tasks.add(new StateExecutionTask(s, reexecutions));
        }
        return bulkExecuteTasks(tasks);
    }

    public List<ITask> bulkExecuteStateTasks(State... states) {
        return this.bulkExecuteStateTasks(new ArrayList<>(Arrays.asList(states)));
    }

    public List<ITask> bulkExecuteTasks(List<TlsTask> taskList) {
        List<Future<ITask>> futureList = new LinkedList<>();
        List<ITask> ret = new ArrayList<>(futureList.size());
        for (TlsTask tlStask : taskList) {
            futureList.add(addTask(tlStask));
        }
        for (Future<ITask> future : futureList) {
            try {
                ret.add(future.get());
            } catch (InterruptedException | ExecutionException ex) {
                ret.add(null);
                throw new RuntimeException("Failed to execute tasks!", ex);
            }
        }
        return ret;
    }

    public List<ITask> bulkExecuteTasks(TlsTask... tasks) {
        return this.bulkExecuteTasks(new ArrayList<>(Arrays.asList(tasks)));
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
