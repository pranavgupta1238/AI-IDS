pipeline {
    agent any

    stages {
        stage('Clone Code') {
            steps {
                echo 'Code already present from repo'
            }
        }

        stage('Build Docker') {
            steps {
                sh 'docker-compose build'
            }
        }

        stage('Run Containers') {
            steps {
                sh 'docker-compose -p capstone_project up -d'
                // sh 'docker-compose down || true'
                // sh 'docker-compose up -d'
            }
        }

        stage('Verify') {
            steps {
                sh 'docker ps'
            }
        }
    }
}