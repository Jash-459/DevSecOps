    //   ____  ____   ___  __  __ 
	//  / ___|| __ ) / _ \|  \/  |
	//  \___ \|  _ \| | | | |\/| |
	//   ___) | |_) | |_| | |  | |
	//  |____/|____/ \___/|_|  |_|

	stage('SBOM & Vulnerability Scan') {
	  when {
		expression {
		  return env.BRANCH_NAME == 'name'
		}
	  }
	  steps {
		catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
		  script {
			echo 'Starting SBOM generation and vulnerability scan...'

			// Ensure tools are installed
			sh '''
			  set -e
			  command -v syft >/dev/null 2>&1 || (echo "Installing Syft..." && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin)
			  command -v grype >/dev/null 2>&1 || (echo "Installing Grype..." && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin)
			  command -v jq >/dev/null 2>&1 || (echo "Installing jq..." && apt-get update && apt-get install -y jq)
			'''

			// Generate SBOM
			echo 'Generating SBOM using Syft...'
			sh 'syft dir:. -o cyclonedx-json > sbom.cdx.json'

			// Convert SBOM to CSV
			echo 'Converting SBOM JSON to CSV...'
			sh '''
			  jq -r '
				["Component Name", "Version", "Type", "Package URL"],
				(.components[] | [.name, .version, .type, .purl])
				| @csv
			  ' sbom.cdx.json > sbom.csv
			'''

			// Scan with Grype
			echo 'Running Grype vulnerability scan...'
			sh 'grype sbom:sbom.cdx.json -o json > grype-report.json'

			// Convert Grype JSON to CSV (with current/fixed versions adjacent)
			echo 'Converting Grype report to CSV...'
			sh '''
			  jq -r '
			  ["Package", "Current Version", "Fixed Version(s)", "Severity", "Type", "Vulnerability ID"],
			  (.matches[] | [
				.artifact.name,
				.artifact.version,
				(if .vulnerability.fix.versions then (.vulnerability.fix.versions | join(", ")) else "" end),
				.vulnerability.severity,
				.artifact.type,
				.vulnerability.id
			  ]) | @csv
			' grype-report.json > grype-report.csv
			'''

			// Archive only CSV reports
			echo 'Archiving CSV reports only...'
			archiveArtifacts artifacts: 'sbom.csv, grype-report.csv', fingerprint: true
		  }
		}
	  }
	}