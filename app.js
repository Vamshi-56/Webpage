document.addEventListener('DOMContentLoaded', function() {
    // Initialize all components
    initDashboard();
    initEmailPhishing();
    initMalwareDetection();
    initIDS();
    initFakeNews();
    initInsiderThreat();
    
    // Simulate loading data
    setTimeout(() => {
        updateDashboardStats();
        simulateInitialData();
    }, 1000);
});

// Dashboard Functions
function initDashboard() {
    // Initialize dashboard charts
    const ctx = document.getElementById('threatTrendChart').getContext('2d');
    const threatTrendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
            datasets: [
                {
                    label: 'Phishing Attempts',
                    data: [12, 19, 15, 27, 34, 42, 38],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Malware Detected',
                    data: [8, 12, 6, 14, 18, 22, 15],
                    borderColor: '#f39c12',
                    backgroundColor: 'rgba(243, 156, 18, 0.1)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Intrusion Attempts',
                    data: [5, 8, 10, 15, 22, 28, 24],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.3,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Threat Trends Over Time',
                    font: {
                        size: 16
                    }
                },
                legend: {
                    position: 'top',
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Incidents'
                    }
                }
            }
        }
    });
}

function updateDashboardStats() {
    // Animate stats counting up
    animateValue('email-threats', 0, 142, 1500);
    animateValue('malware-detected', 0, 87, 1500);
    animateValue('intrusion-attempts', 0, 65, 1500);
    animateValue('fake-news-count', 0, 113, 1500);
}

function animateValue(id, start, end, duration) {
    let startTimestamp = null;
    const element = document.getElementById(id);
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        element.innerHTML = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

// Email Phishing Functions
function initEmailPhishing() {
    document.getElementById('analyze-email').addEventListener('click', analyzeEmail);
}

function analyzeEmail() {
    const emailContent = document.getElementById('email-content').value;
    if (!emailContent.trim()) {
        alert('Please enter email content to analyze');
        return;
    }
    
    // Show loading state
    const resultDetails = document.getElementById('phishing-details');
    resultDetails.innerHTML = '<p>Analyzing email content...</p>';
    
    // Simulate analysis delay
    setTimeout(() => {
        // This would be replaced with actual analysis in a real application
        const phishingScore = calculatePhishingScore(emailContent);
        const confidencePercent = Math.min(Math.floor(phishingScore * 100), 100);
        
        // Update confidence meter
        document.getElementById('phishing-confidence').style.width = `${confidencePercent}%`;
        document.getElementById('phishing-percent').textContent = `${confidencePercent}%`;
        
        // Update result details
        let resultText = '';
        if (confidencePercent > 70) {
            resultText = `<p><strong>High confidence</strong> this is a phishing attempt (${confidencePercent}%).</p>`;
        } else if (confidencePercent > 30) {
            resultText = `<p><strong>Suspicious</strong> email detected (${confidencePercent}% confidence). Exercise caution.</p>`;
        } else {
            resultText = `<p>This email appears to be <strong>legitimate</strong> (${confidencePercent}% phishing confidence).</p>`;
        }
        resultDetails.innerHTML = resultText;
        
        // Show red flags
        const redFlags = detectRedFlags(emailContent);
        const redFlagsContainer = document.getElementById('phishing-red-flags');
        if (redFlags.length > 0) {
            let flagsHTML = '<h4>Potential Red Flags:</h4><ul>';
            redFlags.forEach(flag => {
                flagsHTML += `<li>${flag}</li>`;
            });
            flagsHTML += '</ul>';
            redFlagsContainer.innerHTML = flagsHTML;
        } else {
            redFlagsContainer.innerHTML = '<p>No obvious red flags detected.</p>';
        }
    }, 1500);
}

function calculatePhishingScore(email) {
    // Simple heuristic-based scoring (in a real app, this would be more sophisticated)
    let score = 0;
    
    // Check for urgency
    if (email.match(/urgent|immediately|quick|action required/gi)) score += 0.2;
    
    // Check for requests for personal info
    if (email.match(/password|account|verify|login|credentials|social security/gi)) score += 0.3;
    
    // Check for suspicious links
    if (email.match(/http:\/\/|https:\/\/.*\..*\/.+/gi)) {
        const links = email.match(/http:\/\/|https:\/\/.*\..*\/.+/gi);
        let suspiciousLinks = 0;
        links.forEach(link => {
            if (!link.match(/https:\/\/[a-zA-Z0-9.-]*(company.com|ourdomain.org)/gi)) {
                suspiciousLinks++;
            }
        });
        score += Math.min(suspiciousLinks * 0.15, 0.4);
    }
    
    // Check for poor grammar
    const grammarErrors = countGrammarErrors(email);
    score += Math.min(grammarErrors * 0.05, 0.2);
    
    return Math.min(score, 1);
}

function detectRedFlags(email) {
    const flags = [];
    
    if (email.match(/urgent|immediately|quick|action required/gi)) {
        flags.push('Creates sense of urgency');
    }
    
    if (email.match(/password|account|verify|login|credentials|social security/gi)) {
        flags.push('Requests sensitive information');
    }
    
    const links = email.match(/http:\/\/|https:\/\/.*\..*\/.+/gi) || [];
    links.forEach(link => {
        if (!link.match(/https:\/\/[a-zA-Z0-9.-]*(company.com|ourdomain.org)/gi)) {
            flags.push(`Suspicious link: ${link}`);
        }
    });
    
    if (countGrammarErrors(email) > 3) {
        flags.push('Poor grammar/spelling (common in phishing)');
    }
    
    return flags;
}

function countGrammarErrors(text) {
    // Very simplistic grammar check - would be more sophisticated in real app
    const commonErrors = [
        'dear customer', 'dear user', 'dear account holder', // Generic greetings
        'kindly', 'revert back', 'do the needful', // Non-standard phrases
        /[A-Z]{3,}/g, // Excessive capitalization
        /[!]{2,}/g // Multiple exclamation points
    ];
    
    let errorCount = 0;
    commonErrors.forEach(pattern => {
        const matches = text.match(pattern) || [];
        errorCount += matches.length;
    });
    
    return errorCount;
}

// Malware Detection Functions
function initMalwareDetection() {
    const fileUpload = document.getElementById('file-upload');
    const fileInfo = document.getElementById('file-info');
    
    fileUpload.addEventListener('change', function(e) {
        if (this.files.length > 0) {
            fileInfo.textContent = this.files[0].name;
        } else {
            fileInfo.textContent = 'No file selected';
        }
    });
    
    document.getElementById('scan-file').addEventListener('click', scanFile);
}

function scanFile() {
    const fileInput = document.getElementById('file-upload');
    if (fileInput.files.length === 0) {
        alert('Please select a file to scan');
        return;
    }
    
    const file = fileInput.files[0];
    const checkBehavior = document.getElementById('check-behavior').checked;
    const checkSignature = document.getElementById('check-signature').checked;
    
    // Show loading state
    const resultDetails = document.getElementById('malware-details');
    resultDetails.innerHTML = `<p>Scanning ${file.name} (${formatFileSize(file.size)})...</p>`;
    
    // Initialize chart
    const ctx = document.getElementById('malwareBehaviorChart').getContext('2d');
    if (window.malwareBehaviorChart) {
        window.malwareBehaviorChart.destroy();
    }

    window.malwareBehaviorChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['File Behavior', 'Signature Check', 'File Size', 'Malware Detection'],
            datasets: [{
                label: 'Malware Analysis',
                data: [Math.random() * 100, Math.random() * 100, Math.random() * 100, Math.random() * 100],
                backgroundColor: 'rgba(241, 196, 15, 0.1)',
                borderColor: '#f39c12',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Malware Detection Analysis',
                    font: { size: 16 }
                },
                legend: {
                    position: 'top',
                }
            }
        }
    });

    // Simulate malware detection process
    setTimeout(() => {
        // In a real-world app, this would involve actual file analysis and detection
        const detectionResult = Math.random() > 0.5 ? 'Malware detected' : 'No malware detected';
        resultDetails.innerHTML = `<p><strong>${detectionResult}</strong></p>`;
    }, 2000);
}

function formatFileSize(size) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (size >= 1024 && i < units.length - 1) {
        size /= 1024;
        i++;
    }
    return size.toFixed(2) + ' ' + units[i];
}

// IDS Simulation Functions
function initIDS() {
    document.getElementById('start-simulation').addEventListener('click', startIDSSimulation);
}

function startIDSSimulation() {
    const simulationDetails = document.getElementById('simulation-details');
    simulationDetails.innerHTML = '<p>Simulating intrusion detection...</p>';

    // Simulate IDS process
    setTimeout(() => {
        const intrusionAttempt = Math.random() > 0.5 ? 'Intrusion attempt detected' : 'No intrusion detected';
        simulationDetails.innerHTML = `<p><strong>${intrusionAttempt}</strong></p>`;
    }, 3000);
}

// Fake News / Cyber Scam Article Classifier
function initFakeNews() {
    document.getElementById('classify-article').addEventListener('click', classifyArticle);
}

function classifyArticle() {
    const articleContent = document.getElementById('article-content').value;
    if (!articleContent.trim()) {
        alert('Please enter article content to classify');
        return;
    }

    const resultDetails = document.getElementById('fake-news-details');
    resultDetails.innerHTML = '<p>Classifying article...</p>';

    // Simulate article classification process
    setTimeout(() => {
        const scamProbability = Math.random() * 100;
        const resultText = scamProbability > 50
            ? `<p><strong>Cyber Scam detected</strong> with ${scamProbability.toFixed(2)}% confidence.</p>`
            : `<p><strong>Article seems legitimate</strong> with ${scamProbability.toFixed(2)}% confidence.</p>`;
        resultDetails.innerHTML = resultText;
    }, 2000);
}

// Insider Threat Prediction Functions
function initInsiderThreat() {
    document.getElementById('predict-behavior').addEventListener('click', predictInsiderBehavior);
}

function predictInsiderBehavior() {
    const userBehavior = document.getElementById('user-behavior').value;
    if (!userBehavior.trim()) {
        alert('Please enter behavior data to predict');
        return;
    }

    const resultDetails = document.getElementById('insider-threat-details');
    resultDetails.innerHTML = '<p>Predicting insider threat...</p>';

    // Simulate prediction
    setTimeout(() => {
        const threatProbability = Math.random() * 100;
        const resultText = threatProbability > 60
            ? `<p><strong>Insider threat predicted</strong> with ${threatProbability.toFixed(2)}% probability.</p>`
            : `<p><strong>No insider threat detected</strong> with ${threatProbability.toFixed(2)}% probability.</p>`;
        resultDetails.innerHTML = resultText;
    }, 2000);
}

// Adding smooth scrolling for navigation
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Mobile responsive hamburger menu toggle
const menuToggle = document.getElementById('menu-toggle');
const navMenu = document.getElementById('nav-menu');

menuToggle.addEventListener('click', function() {
    navMenu.classList.toggle('active');
});
