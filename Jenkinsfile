pipeline {
    agent any

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        // rustup installs land here; Jenkins agents rarely have it on PATH.
        PATH = "${env.HOME}/.cargo/bin:${env.PATH}"
        CARGO_TERM_COLOR = 'always'
    }

    stages {
        stage('Lint') {
            steps {
                sh 'cargo fmt --check'
            }
        }
        stage('Test') {
            steps {
                sh 'cargo test'
            }
        }
        // Before Build: build.rs embeds console/dist into the binary.
        stage('Console') {
            steps {
                sh 'npm --prefix console ci'
                sh 'npm --prefix console run build'
            }
        }
        stage('Build') {
            steps {
                sh 'cargo build --release'
            }
        }
        // After Build: the TS suite spawns target/release/neleus-db.
        stage('SDKs') {
            steps {
                sh 'cargo test --manifest-path sdk/rust/Cargo.toml'
                sh 'cargo check --manifest-path sdk/python-native/Cargo.toml'
                sh 'npm --prefix sdk/typescript ci'
                sh 'npm --prefix sdk/typescript test'
            }
        }
    }
}
