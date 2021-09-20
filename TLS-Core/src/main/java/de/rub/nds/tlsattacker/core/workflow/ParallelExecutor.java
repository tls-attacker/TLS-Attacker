/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
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

    private final ThreadPoolExecutor executorService;
    private Callable<Integer> timeoutAction;

    private final int size;
    private boolean shouldShutdown = false;

    private final int reexecutions;

    private Callable<Integer> defaultBeforeTransportPreInitCallback = null;

    private Callable<Integer> defaultBeforeTransportInitCallback = null;

    private Callable<Integer> defaultAfterTransportInitCallback = null;

    private Callable<Integer> defaultAfterExecutionCallback = null;

    public ParallelExecutor(int size, int reexecutions, ThreadPoolExecutor executorService) {
        this.executorService = executorService;
        this.reexecutions = reexecutions;
        this.size = size;
        if (reexecutions < 0) {
            throw new IllegalArgumentException("Reexecutions is below zero");
        }
    }

    public ParallelExecutor(ThreadPoolExecutor executorService, int reexecutions) {
        // TODO check whether this constructor is still used or whether it could be removed
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

    private Future<ITask> addTask(TlsTask task) {
        if (executorService.isShutdown()) {
            throw new RuntimeException("Cannot add Tasks to already shutdown executor");
        }
        if (defaultBeforeTransportPreInitCallback != null && task.getBeforeTransportPreInitCallback() == null) {
            task.setBeforeTransportPreInitCallback(defaultBeforeTransportPreInitCallback);
        }
        if (defaultBeforeTransportInitCallback != null && task.getBeforeTransportInitCallback() == null) {
            task.setBeforeTransportInitCallback(defaultBeforeTransportInitCallback);
        }
        if (defaultAfterTransportInitCallback != null && task.getAfterTransportInitCallback() == null) {
            task.setAfterTransportInitCallback(defaultAfterTransportInitCallback);
        }
        if (defaultAfterExecutionCallback != null && task.getAfterExecutionCallback() == null) {
            task.setAfterExecutionCallback(defaultAfterExecutionCallback);
        }
        return executorService.submit(task);
    }

    private Future<ITask> addStateTask(State state) {
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

    public List<ITask> bulkExecuteTasks(List<TlsTask> taskList) {
        List<Future<ITask>> futureList = new LinkedList<>();
        List<ITask> resultList = new ArrayList<>(futureList.size());
        for (TlsTask tlStask : taskList) {
            futureList.add(addTask(tlStask));
        }
        for (Future<ITask> future : futureList) {
            try {
                resultList.add(future.get());
            } catch (InterruptedException | ExecutionException ex) {
                throw new RuntimeException("Failed to execute tasks!", ex);
            }
        }
        return resultList;
    }

    public List<ITask> bulkExecuteTasks(TlsTask... tasks) {
        return this.bulkExecuteTasks(new ArrayList<>(Arrays.asList(tasks)));
    }

    public int getSize() {
        return size;
    }

    public void shutdown() {
        shouldShutdown = true;
        executorService.shutdown();
    }

    /**
     * Creates a new thread monitoring the executorService. If the time since the last {@link TlsTask} was finished
     * exceeds the timeout, the function assiged to {@link ParallelExecutor#timeoutAction } is executed. The
     * {@link ParallelExecutor#timeoutAction } function can, for example, try to restart the client/server, so that the
     * remaining {@link TlsTask}s can be finished.
     *
     * @param timeout
     *                The timeout in milliseconds
     *
     */
    public void armTimeoutAction(int timeout) {
        if (timeoutAction == null) {
            LOGGER.warn("No TimeoutAction set, this won't do anything");
            return;
        }

        new Thread(() -> {
            monitorExecution(timeout);
        }).start();
    }

    private void monitorExecution(int timeout) {
        long timeoutTime = System.currentTimeMillis() + timeout;
        long lastCompletedCount = 0;
        while (!shouldShutdown) {
            long completedCount = executorService.getCompletedTaskCount();
            if (executorService.getActiveCount() == 0 || completedCount != lastCompletedCount) {
                timeoutTime = System.currentTimeMillis() + timeout;
                lastCompletedCount = completedCount;
            } else if (System.currentTimeMillis() > timeoutTime) {
                LOGGER.debug("Timeout");
                try {
                    int exitCode = timeoutAction.call();
                    if (exitCode != 0) {
                        throw new RuntimeException("TimeoutAction did terminate with code " + exitCode);
                    }
                    timeoutTime = System.currentTimeMillis() + timeout;
                } catch (Exception e) {
                    LOGGER.warn("TimeoutAction did not succeed", e);
                }
            }
        }
    }

    public int getReexecutions() {
        return reexecutions;
    }

    public Callable<Integer> getTimeoutAction() {
        return timeoutAction;
    }

    public void setTimeoutAction(Callable<Integer> timeoutAction) {
        this.timeoutAction = timeoutAction;
    }

    public Callable<Integer> getDefaultBeforeTransportPreInitCallback() {
        return defaultBeforeTransportPreInitCallback;
    }

    public void setDefaultBeforeTransportPreInitCallback(Callable<Integer> defaultBeforeTransportPreInitCallback) {
        this.defaultBeforeTransportPreInitCallback = defaultBeforeTransportPreInitCallback;
    }

    public Callable<Integer> getDefaultBeforeTransportInitCallback() {
        return defaultBeforeTransportInitCallback;
    }

    public void setDefaultBeforeTransportInitCallback(Callable<Integer> defaultBeforeTransportInitCallback) {
        this.defaultBeforeTransportInitCallback = defaultBeforeTransportInitCallback;
    }

    public Callable<Integer> getDefaultAfterTransportInitCallback() {
        return defaultAfterTransportInitCallback;
    }

    public void setDefaultAfterTransportInitCallback(Callable<Integer> defaultAfterTransportInitCallback) {
        this.defaultAfterTransportInitCallback = defaultAfterTransportInitCallback;
    }

    public Callable<Integer> getDefaultAfterExecutionCallback() {
        return defaultAfterExecutionCallback;
    }

    public void setDefaultAfterExecutionCallback(Callable<Integer> defaultAfterExecutionCallback) {
        this.defaultAfterExecutionCallback = defaultAfterExecutionCallback;
    }

}
