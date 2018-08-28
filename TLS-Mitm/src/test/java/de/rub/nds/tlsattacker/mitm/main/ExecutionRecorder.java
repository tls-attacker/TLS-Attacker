/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.mitm.main;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.layout.PatternLayout;
import static org.junit.Assert.fail;

/**
 * Simulate module execution and record all console output. Allows building
 * simple integration tests based on expected command line output.
 *
 * Temporarily redirects System.{out,err}.
 *
 */
public class ExecutionRecorder {

    /**
     * Kill executed module after timeout milliseconds
     */
    private final int timeout;
    private final String expected;
    private final String[] parameters;
    private final Level logLevel;
    private String recordedOutput;

    public ExecutionRecorder(String[] parameters, String expected, int timeout, Level logLevel) {
        this.timeout = timeout;
        this.expected = expected;
        this.parameters = parameters;
        this.logLevel = logLevel;
    }

    public void run() {

        addFollowConsoleAppender();

        TlsMitm mitm = new TlsMitm(parameters);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        PrintStream output = new PrintStream(record);
        PrintStream console = System.out;
        PrintStream errconsole = System.err;

        try {
            System.setOut(output);
            System.setErr(output);
            executor.submit(mitm).get(timeout, TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            // ok
        } catch (InterruptedException | ExecutionException e) {
            fail("Problem spawning TLS-Mitm instance: " + e);
        } finally {
            System.setOut(console);
            System.setErr(errconsole);
        }

        recordedOutput = record.toString();
    }

    public String getRecordedOutput() {
        return recordedOutput;
    }

    public void setRecordedOutput(String recordedOutput) {
        this.recordedOutput = recordedOutput;
    }

    private void addFollowConsoleAppender() {
        final LoggerContext context = LoggerContext.getContext(false);
        final Configuration config = context.getConfiguration();
        final PatternLayout layout = PatternLayout.newBuilder().withPattern("%-5level %c{-4} - %msg%n").build();
        Appender appender = ConsoleAppender.newBuilder().setFollow(true).setTarget(ConsoleAppender.Target.SYSTEM_OUT)
                .withName("ExecutionRecorder").withLayout(layout).build();
        appender.start();
        config.addAppender(appender);
        config.getRootLogger().addAppender(appender, logLevel, null);
    }
}
