# 🤝 Contributing to HoneyCloud-X

Thank you for your interest in contributing to HoneyCloud-X! This document provides guidelines and information for contributors.

## 📋 Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Guidelines](#security-guidelines)
- [Documentation](#documentation)
- [Community](#community)

## 📜 Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Node.js 16+
- Docker & Docker Compose
- Git

### Quick Setup
```bash
# Fork and clone the repository
git clone https://github.com/your-username/honeycloud-x.git
cd honeycloud-x

# Set up development environment
./scripts/setup-dev.sh

# Start development services
./Start-HoneyCloud.ps1
```

## 🛠️ Development Setup

### Backend Development
```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Install dependencies
cd backend
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run backend server
uvicorn app.main:app --reload --port 8000
```

### Frontend Development
```bash
# Install frontend dependencies
cd frontend
npm install

# Start development server
npm run dev

# Run tests
npm run test
```

### Database Setup
```bash
# Start database services
docker-compose up -d postgres redis

# Run migrations
cd backend
alembic upgrade head
```

## 🔄 Contributing Process

### 1. Create an Issue
Before starting work, create an issue to discuss:
- Bug reports
- Feature requests
- Questions or clarifications

### 2. Fork and Branch
```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/your-username/honeycloud-x.git

# Create a feature branch
git checkout -b feature/your-feature-name
```

### 3. Make Changes
- Follow coding standards
- Write tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Commit Changes
```bash
# Stage your changes
git add .

# Commit with descriptive message
git commit -m "feat: add new attack detection algorithm

- Implement ML-based anomaly detection
- Add unit tests for detection logic
- Update API documentation"
```

### 5. Push and Create PR
```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
```

## 📝 Coding Standards

### Python (Backend)
- Follow PEP 8 style guide
- Use Black for code formatting
- Use type hints where possible
- Maximum line length: 88 characters

```python
# Good example
def detect_threat(event_data: Dict[str, Any]) -> ThreatLevel:
    """Detect threat level from event data.
    
    Args:
        event_data: Dictionary containing event information
        
    Returns:
        ThreatLevel enum indicating severity
    """
    if not event_data:
        return ThreatLevel.LOW
    
    return analyze_patterns(event_data)
```

### JavaScript (Frontend)
- Use ESLint with Airbnb configuration
- Use Prettier for formatting
- Prefer const/let over var
- Use meaningful variable names

```javascript
// Good example
const analyzeAttackPattern = (eventData) => {
  if (!eventData || !eventData.source_ip) {
    return { severity: 'LOW', confidence: 0 };
  }
  
  return {
    severity: calculateSeverity(eventData),
    confidence: calculateConfidence(eventData)
  };
};
```

### Git Commit Messages
Follow conventional commits format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

## 🧪 Testing Guidelines

### Backend Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_threat_detection.py

# Run with verbose output
pytest -v
```

### Frontend Testing
```bash
# Run unit tests
npm run test

# Run with coverage
npm run test:coverage

# Run end-to-end tests
npm run test:e2e
```

### Test Requirements
- All new features must have tests
- Bug fixes must include regression tests
- Maintain minimum 80% code coverage
- Tests should be fast and reliable

### Test Structure
```python
# Backend test example
class TestThreatDetection:
    def setup_method(self):
        """Set up test fixtures."""
        self.detector = ThreatDetector()
        self.sample_event = {
            'source_ip': '192.168.1.100',
            'service': 'SSH',
            'timestamp': datetime.now()
        }
    
    def test_detect_brute_force_attack(self):
        """Test brute force attack detection."""
        # Arrange
        events = [self.sample_event] * 10
        
        # Act
        result = self.detector.detect_brute_force(events)
        
        # Assert
        assert result.threat_level == ThreatLevel.HIGH
        assert result.confidence > 0.8
```

## 🔒 Security Guidelines

### Security Best Practices
- Never commit secrets or credentials
- Use environment variables for configuration
- Validate all user inputs
- Follow OWASP security guidelines
- Use parameterized queries for database access

### Security Review Process
- All security-related changes require review
- Run security scans before submitting PR
- Report vulnerabilities privately
- Follow responsible disclosure practices

### Sensitive Data Handling
```python
# Good: Use environment variables
DATABASE_URL = os.getenv('DATABASE_URL')

# Bad: Hardcoded credentials
DATABASE_URL = 'postgresql://user:password@localhost/db'
```

## 📚 Documentation

### Code Documentation
- Use docstrings for all functions and classes
- Include type hints
- Provide usage examples
- Document complex algorithms

### API Documentation
- Update OpenAPI specifications
- Include request/response examples
- Document error codes and messages
- Provide authentication details

### User Documentation
- Update README for new features
- Create tutorials for complex features
- Include screenshots for UI changes
- Maintain changelog

## 🏗️ Architecture Guidelines

### Backend Architecture
- Follow FastAPI best practices
- Use dependency injection
- Implement proper error handling
- Use async/await for I/O operations

### Frontend Architecture
- Use modern JavaScript features
- Implement responsive design
- Follow accessibility guidelines
- Optimize for performance

### Database Design
- Use proper indexing
- Implement data validation
- Follow normalization principles
- Plan for scalability

## 🚀 Performance Guidelines

### Backend Performance
- Use database connection pooling
- Implement caching where appropriate
- Optimize database queries
- Use async operations for I/O

### Frontend Performance
- Minimize bundle size
- Use lazy loading
- Optimize images and assets
- Implement proper caching

## 🐛 Debugging Guidelines

### Backend Debugging
```python
# Use structured logging
import logging

logger = logging.getLogger(__name__)

def process_event(event_data):
    logger.info("Processing event", extra={
        'event_id': event_data.get('id'),
        'source_ip': event_data.get('source_ip')
    })
```

### Frontend Debugging
```javascript
// Use console methods appropriately
console.debug('Debug info:', debugData);
console.warn('Warning:', warningMessage);
console.error('Error:', errorDetails);
```

## 🤝 Community

### Communication Channels
- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: General questions and ideas
- Discord: Real-time chat (link in README)
- Email: security@honeycloud-x.com (security issues)

### Getting Help
1. Check existing documentation
2. Search existing issues
3. Ask in GitHub Discussions
4. Create a new issue with detailed information

### Recognition
Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation
- Annual contributor highlights

## 📋 Checklist for Contributors

Before submitting a PR, ensure:
- [ ] Code follows style guidelines
- [ ] Tests are written and passing
- [ ] Documentation is updated
- [ ] Security considerations addressed
- [ ] Performance impact considered
- [ ] Backward compatibility maintained
- [ ] PR template completed

## 🎉 Thank You!

Your contributions make HoneyCloud-X better for everyone. We appreciate your time and effort in helping improve the project!

For questions about contributing, please reach out through our community channels or create an issue.