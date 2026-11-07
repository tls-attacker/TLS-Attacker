# Dynamic Handshake Handling in TLS-Attacker

This directory contains examples demonstrating how to handle simultaneous full handshake and session resumption scenarios in TLS-Attacker, addressing issue #195.

## Problem Statement

When implementing a TLS server using TLS-Attacker, you may need to handle two different handshake scenarios for a second ClientHello:
1. **Session Resumption**: ClientHello includes the Session ID from a previous session
2. **New Full Handshake**: ClientHello contains an empty Session ID

TLS-Attacker's workflow traces are typically static and don't support conditional branching, making it challenging to handle both cases in a single workflow.

## Solution Approach

The examples demonstrate two approaches to solve this problem:

### 1. Manual Action Execution (`DynamicHandshakeExample.java`)

This approach executes actions individually and makes decisions based on the received messages:

```java
// Execute actions up to decision point
executeAction(new ReceiveAction(new ClientHelloMessage()), state);

// Check received ClientHello
ClientHelloMessage clientHello = findReceivedClientHello(state);
byte[] receivedSessionId = clientHello.getSessionId().getValue();

// Decide which path to take
if (isSessionResumption(receivedSessionId, expectedSessionId)) {
    executeResumptionHandshake(state);
} else {
    executeFullHandshake(state);
}
```

**Advantages:**
- Full control over execution flow
- Easy to implement conditional logic
- Can inspect state between actions

**Disadvantages:**
- More manual code required
- Less integrated with TLS-Attacker's workflow system

### 2. Hybrid Workflow Approach (`DynamicHandshakeWorkflowExample.java`)

This approach uses WorkflowExecutor but modifies the workflow dynamically:

```java
// Execute partial workflow up to decision point
WorkflowTrace initialTrace = new WorkflowTrace();
initialTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
// ... execute initial actions

// Determine handshake type
boolean isResumption = checkSessionResumption(clientHello, expectedSessionId);

// Create and append appropriate continuation workflow
WorkflowTrace continuationTrace = createContinuationWorkflow(isResumption);
state.getWorkflowTrace().addAll(continuationTrace.getTlsActions());

// Continue execution with WorkflowExecutor
executor.executeWorkflow();
```

**Advantages:**
- Uses standard WorkflowExecutor
- Maintains workflow trace for debugging
- More integrated with TLS-Attacker patterns

**Disadvantages:**
- Requires interrupting and resuming workflow execution
- More complex implementation

## Usage Example

To use these examples in your project:

1. **As a library (recommended)**: Create a Maven project that depends on TLS-Attacker and adapt the example code:

```java
public class MyTlsServer {
    public void handleConnection() {
        Config config = createConfig();
        State state = new State(config);
        
        // Execute initial handshake
        byte[] sessionId = executeInitialHandshake(state);
        
        // Handle subsequent connections dynamically
        while (true) {
            ClientHelloMessage hello = receiveClientHello(state);
            if (isResumption(hello, sessionId)) {
                executeResumptionHandshake(state);
            } else {
                executeFullHandshake(state);
            }
        }
    }
}
```

2. **For testing**: Use the test examples to verify your implementation handles both scenarios correctly.

## Key Implementation Details

### Session ID Checking
```java
boolean isResumption = receivedSessionId != null && 
                      receivedSessionId.length > 0 && 
                      Arrays.equals(receivedSessionId, expectedSessionId);
```

### DTLS Cookie Handling
The examples include HelloVerifyRequest handling for DTLS:
```java
executeAction(new SendAction(new HelloVerifyRequestMessage()), state);
executeAction(new ReceiveAction(new ClientHelloMessage()), state); // Second hello after cookie
```

### PSK Configuration
The examples use PSK cipher suites as shown in the original issue:
```java
config.setDefaultSelectedCipherSuite("TLS_PSK_WITH_AES_128_CBC_SHA");
config.setDefaultPSKIdentity("Client_identity".getBytes());
config.setDefaultPSKKey(pskKey);
```

## Testing

Run the included test class to verify the implementation:

```bash
mvn test -Dtest=DynamicHandshakeExampleTest
```

## Further Customization

You can extend these examples to:
- Support multiple session IDs
- Implement session cache/storage
- Add timeout handling for session resumption
- Support other handshake variations (e.g., TLS 1.3 PSK modes)

## References

- Issue #195: Handling Simultaneous Full Handshake and Session Resumption
- TLS-Attacker Documentation: https://github.com/tls-attacker/TLS-Attacker
- TLS Session Resumption: RFC 5246 Section 7.3