@Library('jenkins-ci-library') _

/**
 * Main CI/CD Pipeline for Maven-based projects.
 *
 * This pipeline handles the full build lifecycle: clean, build, tests, static analysis,
 * deployment to Nexus, and optional Maven Release.
 */
pipeline {
    agent any

    environment {
        JDK_TOOL_NAME = 'JDK 21'
        MAVEN_TOOL_NAME = 'Maven 3.9.9'
    }

    options {
        skipStagesAfterUnstable()
        disableConcurrentBuilds abortPrevious: true
        timeout(time: 45, unit: 'MINUTES')
    }

    parameters {
        booleanParam(
                name: 'DEPLOY',
                defaultValue: true,
                description: 'Deploy SNAPSHOT artifacts to internal Nexus (only on main branch)'
        )
        booleanParam(
                name: 'RELEASE',
                defaultValue: true,
                description: 'Perform a Maven Release'
        )
        booleanParam(
                name: 'DRY_RUN',
                defaultValue: true,
                description: 'If true → Simulate release only (nothing is deployed to Nexus)'
        )
        string(
                name: 'RELEASE_VERSION',
                defaultValue: '7.7.1',
                description: 'Release Version (z.B. 1.2.3). Leave empty to use tag name.'
        )
    }

    stages {
        stage('Clean') {
            steps { ciMaven(
                    goal: "clean") }
        }
        stage('Format Check') {
            steps { ciMaven(
                    goal: "spotless:check",
                    timeout: 60) }
        }
        stage('Build') {
            steps {
                ciMaven(
                        goal: "package",
                        args: "-DskipTests=true",
                        timeout: 120)
            }
        }
        stage('Static Analysis & Unit Tests') {
            when {
                expression { pipelineUtils.isMainTagOrChangeRequest() }
            }
            parallel {

                stage('Code Analysis') {
                    steps { ciStepStaticAnalysis() }
                }

                stage('Unit Tests') {
                    steps { ciUnitTests(profile: "coverage") }
                    post {
                        always {
                            junit testResults: '**/target/surefire-reports/TEST-*.xml',
                                    allowEmptyResults: true
                        }
                    }
                }
            }
        }
        stage('Integration Tests') {
            when {
                expression { pipelineUtils.isMainTagOrChangeRequest() }
            }
            steps {
                ciIntegrationTests(profile: "coverage", timeout: 1800)
            }
        }
        stage('Deploy to Internal Nexus Repository') {
            when {
                expression { pipelineUtils.shouldDeploy() }
            }
            steps {
                ciMaven(
                        goal: "deploy",
                        profile: "internal-releases",
                        args: "-DskipTests=true")
            }
        }
        stage('Publish to Maven Central') {
            steps {
                ciCentralPublish(
                        version: params.RELEASE_VERSION,
                        autoPublish: false,
                        skipTests: true,
                        quiet: false,
                        credentialsId: 'central-technical-user-token'
                )
            }
        }
    }
    post {
        always {
            recordIssues enabledForFailure: true, tools: [mavenConsole(), java(), javaDoc()]
        }
    }
}