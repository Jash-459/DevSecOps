      //  ___  ___  _ __   __ _ _ __      ___  ___ __ _ _ __
      // / __|/ _ \| '_ \ / _` | '__|____/ __|/ __/ _` | '_ \
      // \__ \ (_) | | | | (_| | | |_____\__ \ (_| (_| | | | |
      // |___/\___/|_| |_|\__,_|_|       |___/\___\__,_|_| |_|

stage('SonarQube') {
  when {
    expression {
      return env.BRANCH_NAME == 'name'
    }
  }
  environment {
    SONARQUBE_SERVER = 'Sonarqube-server'
    SONARQUBE_URL = 'http://url'
  }
  steps {
    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
    script {
      echo 'Starting full SonarQube scan and report generation...'
      try {
        def sonarScannerHome = tool 'Sonarqube-Scanner'

        // Run Sonar Scanner with token
        withSonarQubeEnv(SONARQUBE_SERVER) {
          withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
            sh "${sonarScannerHome}/bin/sonar-scanner -Dsonar.projectKey=${REPOSITORY_NAME} -Dsonar.sources=. -Dsonar.host.url=${SONARQUBE_URL} -Dsonar.login=${SONAR_TOKEN}"
          }
        }

        // Run sonarapi (optional, ignore failure due to GLIBC issues)
        withCredentials([
          usernamePassword(credentialsId: 'SONARQUBE_CREDENTIALS', usernameVariable: 'SONAR_USER', passwordVariable: 'SONAR_PASS'),
          usernamePassword(credentialsId: 'BITBUCKET', usernameVariable: 'BITBUCKET_USERNAME', passwordVariable: 'BITBUCKET_PASSWORD')
        ]) {
          try {
            sh """
              curl -L -u ${BITBUCKET_USERNAME}:${BITBUCKET_PASSWORD} https://api.bitbucket.org/2.0/repositories/url/sonarapi --output sonarapi
              chmod +x ./sonarapi
              sleep 10
              ./sonarapi -url "${SONARQUBE_URL}" -user "${SONAR_USER}" -pass "${SONAR_PASS}" -projectKey "${REPOSITORY_NAME}" || echo 'sonarapi failed but continuing...'
            """
          } catch (err) {
            echo "Warning: sonarapi execution failed but continuing: ${err}"
          }
        }

        

        // Run Python report script
        withCredentials([string(credentialsId: env.SONAR_TOKEN_CREDENTIALS_ID, variable: 'SONAR_API_TOKEN'),
        usernamePassword(credentialsId: 'BITBUCKET', usernameVariable: 'BITBUCKET_USERNAME', passwordVariable: 'BITBUCKET_PASSWORD')]) {
          echo "Generating SonarQube report for project key: ${env.SONAR_PROJECT}"
          sh """
            set -ex
            export SONAR_API_TOKEN="${SONAR_API_TOKEN}"
            curl -L -u ${BITBUCKET_USERNAME}:${BITBUCKET_PASSWORD} https://api.bitbucket.org/2.0/repositories/url/sonar.py --output sonar.py
            chmod +x ./sonar.py
            python3 sonar.py \\
              --host "${env.SONAR_HOST}" \\
              --project "${env.SONAR_PROJECT}" \\
              --token "${SONAR_API_TOKEN}" \\
              --output "${env.REPORT_NAME}" \\
              --charts-dir "${env.CHARTS_DIR}"
          """
        }

        // Archive generated report and charts
        echo "Archiving report and charts..."
     
        archiveArtifacts artifacts: "${env.REPORT_NAME}", fingerprint: true

      } catch (err) {
        error "Pipeline failed during SonarQube scan and report stage: ${err}"
      }
    }
  }
}
}