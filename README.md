# TLS-Attacker

![GitHub release (latest by date)](https://img.shields.io/github/v/release/tls-attacker/TLS-Attacker)
![licence](https://img.shields.io/badge/License-Apachev2-brightgreen.svg)
[![Build Status](https://hydrogen.cloud.nds.rub.de/buildStatus/icon.svg?job=TLS-Attacker)](https://hydrogen.cloud.nds.rub.de/job/TLS-Attacker/)

TLS-Attacker is a Java-based framework for analyzing TLS libraries. It is able to send arbitrary protocol messages in an arbitrary order to the TLS peer, and define their modifications using a provided interface. This gives the developer an opportunity to easily define a custom TLS protocol flow and test it against his TLS library.

**Please note:**  *TLS-Attacker is a research tool intended for TLS developers and pentesters. There is no GUI and no green/red lights.*

## Compiling and Running
In order to compile and use TLS-Attacker, you need to have Java and Maven installed. On Ubuntu you can install Maven by running:
```bash
$ sudo apt-get install maven
```
TLS-Attacker currently needs Java JDK 8 to run.

If you have the correct Java version you can run the maven command from the TLS-Attacker directory:
```bash
$ git clone https://github.com/tls-attacker/TLS-Attacker.git
$ cd TLS-Attacker
$ mvn clean install
```
Alternatively, if you are in a hurry, you can skip the tests by using:
```bash
$ mvn clean install -DskipTests=true
```
The resulting jar files are placed in the "apps" folder.

If you want to use this project as a dependency, you do not have to compile it yourself and can include it in your pom
.xml as follows.
```xml
<dependency>
    <groupId>de.rub.nds.tlsattacker</groupId>
    <artifactId>TLS-Attacker</artifactId>
    <version>3.8.0</version>
    <type>pom</type>
</dependency>
```

TLS-Attacker ships with demo applications which provide you easy access to TLS-Attacker functionality.

You can run TLS-Attacker as a client with the following command:
```bash
$ cd apps
$ java -jar TLS-Client.jar -connect [host:port]
```
or as a server with:

```bash
$ java -jar TLS-Server.jar -port [port]
```

TLS-Attacker also ships with some example attacks on TLS to show you how easy it is to implement an attack with TLS-Attacker.
You can run those examples with the following command:
```bash
$ java -jar Attacks.jar [Attack] -connect [host:port]
```
Although these example applications are very powerful in itself, TLS-Attacker unleashes its full potential when used as a programming library.

## Code Structure
TLS-Attacker consists of several (maven) projects:
- Attacks: Implementation of some well-known attacks and vulnerability tests
- TLS-Client: The client example application
- TLS-Core: The protocol stack and heart of TLS-Attacker
- TLS-Forensic: Forensic analysis of TLS traffic
- TLS-Mitm: A prototype for MitM workflows
- TLS-Server: The server example application
- Transport: Transport utilities for lower layers
- Utils: A collection of utility classes

![TLS-Attacker design](https://github.com/tls-attacker/TLS-Attacker/blob/master/resources/figures/design.png)

You can find more information about these modules in the Wiki.

## Features
Currently, the following features are supported:
- SSL 3, TLS versions 1.0 (RFC-2246), 1.1 (RFC-4346), 1.2 (RFC-5246), and 1.3 (RFC-8446)
- SSL 2 (Partially supported)
- (EC)DH(E), RSA, PSK, SRP, GOST and ANON key exchange algorithms
- CBC, AEAD and Streamciphers (AES, CAMELLIA, DES, 3DES, IDEA, RC2, ARIA, GOST_28147_CNT_IMIT, RC4, SEED, NULL)
- ~300 Cipher suites, ~30 Extensions
- Client and Server
- HTTPS
- Workflows with more than two parties
- Lots of extensions
- Tokenbinding (EC) and Tokenbinding over HTTP
- Sockets
- TLS 1.3 0-RTT
- STARTTLS
- ...

## Usage
Here we present some very simple examples on using TLS-Attacker.

First, you need to start a TLS server (*please do not use public servers*). Please run the keygen.sh script if not done before. For example, you can use an OpenSSL test server:
```
$ cd TLS-Attacker/resources
$ openssl s_server -key rsa1024key.pem -cert rsa1024cert.pem
```
This command starts a TLS server on a port 4433.

If you want to connect to a server, you can use this command:
```bash
$ cd TLS-Attacker/apps
$ java -jar TLS-Client.jar -connect localhost:4433
```
*Note: If this Handshake fails, it is probably because you did not specify a concrete cipher suite. TLS-Attacker will not completely respect server selected cipher suites.*

You can use a different cipher suite, TLS version, or connect to a different port with the following parameters:
```bash
$ java -jar TLS-Client.jar -connect localhost:4433 -cipher TLS_RSA_WITH_AES_256_CBC_SHA -version TLS11
```

The Attack's module contains some attacks, you can for example test for the padding oracle vulnerabilities:
```bash
$ java -jar Attacks.jar padding_oracle -connect localhost:4433 
```

In case you are a more experienced developer, you can create your own TLS message flow by writing Java code. For example:
```java
Config config = Config.createConfig();
WorkflowTrace trace = new WorkflowTrace();
trace.addTlsAction(new SendAction(new ClientHelloMessage()));
trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
State state = new State(config, trace);
DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
executor.executeWorkflow();
```
TLS-Attacker uses the concept of WorkflowTraces to define a "TLS message flow". A WorkflowTrace consists of a list of actions which are then executed one after the other. Although for a typical "TLS message flow" only SendAction's and ReceiveAction's are needed, the framework does not stop here and implements a lot of different other actions which can be used to execute even more arbitrary message flows. A list of currently implemented actions with explanations can be found in the Wiki.

We know many of you hate Java. Therefore, you can also use an XML structure and run your customized TLS protocol from XML:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workflowTrace>
    <Send>
        <messages>
            <ClientHello>
                <extensions>
                    <ECPointFormat/>
                    <HeartbeatExtension/>
                    <EllipticCurves/>
                </extensions>
            </ClientHello>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <ServerHello>
                <extensions>
                    <ECPointFormat/>
                </extensions>
            </ServerHello>
            <Certificate/>
            <ServerHelloDone/>
        </expectedMessages>
    </Receive>
    <Send>
        <messages>
            <RSAClientKeyExchange>
                <computations/>
            </RSAClientKeyExchange>
            <ChangeCipherSpec/>
            <Finished/>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <ChangeCipherSpec/>
            <Finished/>
        </expectedMessages>
    </Receive>
</workflowTrace>
```
Given this XML structure is located in TLS-Attacker/apps/workflow.xml, you would just need to execute:
```bash
$ java -jar TLS-Client.jar -connect [host]:[port] -workflow_input workflow.xml
```
## Modifiable Variables
TLS-Attacker uses the concept of Modifiable Variables to allow runtime modifications to predefined Workflows. Modifiable variables allow one to set modifications to basic types after or before their values are actually set. When their actual values are determined and one tries to access the value via getters the original value will be returned in a modified form accordingly. More details on this concept can be found at https://github.com/tls-attacker/ModifiableVariable. 

```java
ModifiableInteger i = new ModifiableInteger();
i.setOriginalValue(30);
i.setModification(new AddModification(20));
System.out.println(i.getValue());  // 50
```
In this example, we defined a new ModifiableInteger and set its value to 30. Next, we defined a new modification AddModification which simply returns a sum of two integers. We set its value to 20. If we execute the above program, the result 50 is printed. 

We can of course use this concept by constructing our TLS workflows. Imagine you want to test a server for a heartbleed vulnerability. For this purpose, you need to increase the payload length in the heartbeat request. With TLS-Attacker, you can do this as follows:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workflowTrace>
    <Send>
        <messages>
            <ClientHello>
                <extensions>
                    <ECPointFormat/>
                    <HeartbeatExtension/>
                    <EllipticCurves/>
                </extensions>
            </ClientHello>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <ServerHello>
                <extensions>
                    <ECPointFormat/>
                </extensions>
            </ServerHello>
            <Certificate/>
            <ServerHelloDone/>
        </expectedMessages>
    </Receive>
    <Send>
        <messages>
            <RSAClientKeyExchange>
                <computations/>
            </RSAClientKeyExchange>
            <ChangeCipherSpec/>
            <Finished/>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <ChangeCipherSpec/>
            <Finished/>
        </expectedMessages>
    </Receive>
    <Send>
        <messages>
            <Heartbeat>
                <payloadLength>
                    <IntegerExplicitValueModification>
                        <explicitValue>20000</explicitValue>
                    </IntegerExplicitValueModification>
                </payloadLength>
            </Heartbeat>
        </messages>
    </Send>
    <Receive>
        <messages>
            <Heartbeat/>
        </messages>
    </Receive>
</workflowTrace>
```
As you can see, we explicitly increased the payload length of the heartbeat message by 20000.
If you run the attack against the vulnerable server (e.g., OpenSSL 1.0.1f), you should see a valid heartbeat response.

Further examples on attacks and further explanations on TLS-Attacker can be found in the wiki.

## Advanced Features
Some actions require context, or configuration to be executed correctly. For example, if TLS-Attacker tries to send a ClientHello message, it needs to know which values to
put into the message, e.g., which Cipher suites or which protocol version to use. TLS-Attacker draws this information
 from a configuration file (default located in TLS-Core/src/main/resources/default_config.xml).
Values which are determined at runtime are stored in the TlsContext. When a value which is normally selected from the context is missing (because a message was not yet received), the default value from the Config is selected. You can specify your own configuration file from command line with the "-config" parameter. Note that if you do not explicitly define a default value in the config file, TLS-Attacker fills
this gap with hardcoded values (which are equal to the provided default config). More details on how to customize TLS-Attacker can be found in the wiki.

## Acknowledgements
The following people have contributed code to the TLS-Attacker project:
- Florian Pfützenreuter: DTLS 1.2
- Felix Lange: EAP-TLS
- Philip Riese: Server implementation, TLS Man-in-the-Middle prototype
- Christian Mainka: Design support and many implementation suggestions
- Matthias Terlinde: More TLS-Extensions
- Nurullah Erinola: TLS 1.3 Support
- Lucas Hartmann: TLS-MitM Workflows
- Florian Linsner: PSK, SRP
- Pierre Tilhaus: Code quality improvements
- Felix Kleine-Wilde: SSL 3 Support
- Marcel Maehren: 0-RTT Support
- Asli Yardim: STARTTLS
- Tim Reisach: GOST
- Paul Fiterau Brostean: DTLS reintegration
- Malte Poll: High precision timing measurements
- Mario Korth: Client Authentication Analysis
- Nils Hanke: OCSP
Additionally we would like to thank all the other people who have contributed code to the project.

Further contributions and pull requests are welcome.

## TLS-Attacker Projects
The basic concepts behind TLS-Attacker and several attacks are described in the following paper:
- Juraj Somorovsky. Systematic Fuzzing and Testing of TLS Libraries. ACM CCS'16. https://www.nds.rub.de/research/publications/systematic-fuzzing-and-testing-tls-libraries

TLS-Attacker was furthermore used in the following scientific papers and projects:
- Tibor Jager, Jörg Schwenk, Juraj Somorovsky. On the Security of TLS 1.3 and QUIC Against Weaknesses in PKCS#1 v1.5 Encryption. ACM CCS'15. https://www.nds.rub.de/research/publications/ccs15/
- Tibor Jager, Jörg Schwenk, Juraj Somorovsky. Practical Invalid Curve Attacks on TLS-ECDH. ESORICS'15. https://www.nds.rub.de/research/publications/ESORICS15/
- Quellcode-basierte Untersuchung von kryptographisch relevanten Aspekten der OpenSSL-Bibliothek. https://www.bsi.bund.de/DE/Publikationen/Studien/OpenSSL-Bibliothek/opensslbibliothek.html
- Entwicklung einer sicheren Kryptobibliothek. https://www.bsi.bund.de/DE/Themen/Kryptografie_Kryptotechnologie/Kryptografie/Kryptobibliothek/kryptobibliothek_node.html
- Yuan Xiao, Mengyuan Li, Sanchuan Chen, Yinqian Zhang. Stacco: Differentially Analyzing Side-Channel Traces for Detecting SSL/TLS Vulnerabilities in Secure Enclaves. CCS'17. http://web.cse.ohio-state.edu/~zhang.834/papers/ccs17a.pdf

If you have any research ideas or need support feel free to contact us on Twitter (@ic0nz1 , @jurajsomorovsky ) or at https://www.hackmanit.de/.

If TLS-Attacker helps you to find a bug in a TLS implementation, please acknowledge this tool. Thank you!
