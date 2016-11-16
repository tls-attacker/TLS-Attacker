/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.executor;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * A thread pool which blocks once the the queque is full
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class BlockingThreadPoolExecutor extends ThreadPoolExecutor {

    /**
     * Semaphore that blocks the Executor
     */
    private final Semaphore semaphore;

    public BlockingThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit,
            BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue, threadFactory);
        this.semaphore = new Semaphore(maximumPoolSize);
    }

    @Override
    public void execute(Runnable task) {
        boolean acquired = false;
        do {
            try {
                semaphore.acquire();
                acquired = true;
            } catch (InterruptedException e) { // wait forever!
            }
        } while (!acquired);
        try {
            super.execute(task);
        } catch (RuntimeException e) {
            // specifically, handle RejectedExecutionException
            e.printStackTrace();
            semaphore.release();
            throw e;
        } catch (Error e) {
            e.printStackTrace();
            semaphore.release();
            throw e;
        }
    }

    @Override
    protected void afterExecute(Runnable r, Throwable t) {
        semaphore.release();
    }

    private static final Logger LOG = Logger.getLogger(BlockingThreadPoolExecutor.class.getName());
}
