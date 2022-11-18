pipeline {
    agent any

    environment {
        JDK_TOOL_NAME = 'JDK 11'
        MAVEN_TOOL_NAME = 'Maven 3.8.6'
    }

    options {
        skipStagesAfterUnstable()
        disableConcurrentBuilds abortPrevious: true
    }

    stages {
        stage('Clean') {
            steps {
                // This is necessary to make the origin/master refspec available to spotless (for ratcheting)
                withCredentials([gitUsernamePassword(credentialsId: 'github-app-tls-attacker')]) {
                    sh 'git fetch origin master:refs/remotes/origin/master'
                }
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn clean'
                }
            }
        }
        stage('Format Check') {
            options {
                timeout(activity: true, time: 60, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn spotless:check'
                }
            }
        }
        stage('Build') {
            options {
                timeout(activity: true, time: 120, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -DskipTests=true package'
                }
            }

            post {
                success {
                    archiveArtifacts artifacts: '**/target/*.jar'
                }
            }
        }
        stage('Code Analysis') {
            when {
                anyOf {
                    branch 'master'
                    tag 'v*'
                    changeRequest()
                }
            }
            options {
                timeout(activity: true, time: 240, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    // `package` goal is required here to load modules in reactor and avoid dependency resolve conflicts
                    sh 'mvn -DskipTests=true package pmd:pmd pmd:cpd spotbugs:spotbugs'
                }
            }
            post {
                always {
                    recordIssues enabledForFailure: true, tools: [spotBugs(), cpd(pattern: '**/target/cpd.xml'), pmdParser(pattern: '**/target/pmd.xml')]
                }
            }
        }
        stage('Unit Tests') {
            when {
                anyOf {
                    branch 'master'
                    tag 'v*'
                    changeRequest()
                }
            }
            options {
                timeout(activity: true, time: 180, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -P coverage -Dskip.failsafe.tests=true test'
                }
            }
            post {
                always {
                    junit testResults: '**/target/surefire-reports/TEST-*.xml'
                }
            }
        }
        stage('Integration Tests') {
            when {
                anyOf {
                    branch 'master'
                    tag 'v*'
                    changeRequest()
                }
            }
            options {
                timeout(activity: true, time: 300, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -P coverage -Dskip.surefire.tests=true verify'
                }
            }
            post {
                always {
                    junit testResults: '**/target/failsafe-reports/TEST-*.xml', allowEmptyResults: true
                }
                success {
                    publishCoverage adapters: [jacoco(mergeToOneReport: true, path: '**/target/site/jacoco/jacoco.xml')]
                }
            }
        }
        stage('Deploy to Internal Nexus Repository') {
            when {
                anyOf {
                    branch 'master'
                    tag 'v*'
                }
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    // Tests were already executed separately, so disable tests within this step
                    sh 'mvn -DskipTests=true deploy'
                }
            }
        }
    }
    post {
        always {
            recordIssues enabledForFailure: true, tools: [mavenConsole(), java(), javaDoc()]
        }
    }
}