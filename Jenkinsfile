@Library('jenkins-ci-library') _

pipeline {
    agent any

    environment {
        JDK_TOOL_NAME = 'JDK 21'
        MAVEN_TOOL_NAME = 'Maven 3.9.9'
    }

    options {
        skipStagesAfterUnstable()
        disableConcurrentBuilds abortPrevious: true
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
                ciIntegrationTests(profile: "coverage", timeout: 600)
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
    }
    post {
        always {
            recordIssues enabledForFailure: true, tools: [mavenConsole(), java(), javaDoc()]
        }
    }
}
