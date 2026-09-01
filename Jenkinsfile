@Library('jenkins-ci-library') _

@Library('jenkins-ci-library') _

standardPipeline(
        jdkTool: 'JDK 21',
        mavenTool: 'Maven 3.9.9',
        spotlessTimeout: 60,
        buildTimeout: 120,
        intTestTimeout: 600,
        codeAnalyseTimeout: 240,
        uniTestTimeout: 180,

        extraStages: {
            setVersion(
                    projectName: 'tls.attacker'
            )
            centralPublish(
                    autoPublish: false,
                    skipTests: true,
                    quiet: false,
                    useSettings: true,
                    settingsId: 'central-settings',
                    profile: '!protocol-attacker,central-release'
            )
        }
)