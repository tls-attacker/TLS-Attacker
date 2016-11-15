package tlsattacker.fuzzer.executor;

import java.util.concurrent.Callable;
import java.util.concurrent.RunnableFuture;
import tlsattacker.fuzzer.result.Result;

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
/**
 * The Executor classes should Implement the Execution of a FuzzingVector. The
 * Executor itself has to make sure that the Agent is up and running. The
 * Executor should implement all the logic in the run, method, so that parallel
 * fuzzing can be supported. method,
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Executor implements Callable<Result> {
}
