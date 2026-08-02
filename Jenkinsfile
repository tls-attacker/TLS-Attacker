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
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Standard Pipeline') {
            steps {
                script {
                    def standard = load 'jenkins/standardStages.groovy'
                    standard.run(
                            spotlessTimeout: 60,
                            buildTimeout: 120,
                            intTestTimeout: 1800
                    )
                }
            }
        }
    }
}