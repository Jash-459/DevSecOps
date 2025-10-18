//    ______          __      _____ _____  
//   / __ \ \        / /\    / ____|  __ \ 
//  | |  | \ \  /\  / /  \  | (___ | |__) |
//  | |  | |\ \/  \/ / /\ \  \___ \|  ___/ 
//  | |__| | \  /\  / ____ \ ____) | |     
//   \____/   \/  \/_/    \_\_____/|_|     
                                        
 stage('OWASP Scan') {
  when {
    expression {
      return env.BRANCH_NAME == 'name'
    }
  }
  environment{
      NVD_API_KEY=credentials('NVD_API_KEY')
  }
  steps {
    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
      script {
        echo 'Running OWASP Scans'
        dependencyCheck additionalArguments: '--scan ./ --format CSV --format XML --project $REPOSITORY_NAME --nvdApiKey $NVD_API_KEY --out / ', odcInstallation: 'OWASP'
        dependencyCheckPublisher pattern: 'dependency-check-report.xml'
        archiveArtifacts artifacts: 'dependency-check-report.csv', fingerprint: true
      }
    }
  }
}