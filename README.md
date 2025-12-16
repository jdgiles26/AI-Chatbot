# AI Chatbot using NLP & TensorFlow

An intelligent chatbot built with Python, TensorFlow, and Natural Language Processing (NLP). This project demonstrates how to build and deploy a simple conversational AI capable of understanding user intent and generating relevant responses.

Additionally, this repository includes a Mac Mini M2 optimized security assistant CLI tool that performs comprehensive file system analysis and security risk assessment.

## Features

### AI Chatbot
- Intent recognition using custom-trained LSTM model
- Clean, structured NLP pipeline (tokenization, stemming, vectorization)
- FastAPI-powered backend for real-time chatbot responses
- Easy to train and customize with new intents
- Deployment-ready for Render, Hugging Face Spaces, or local Docker

### Security Assistant CLI (Mac Mini M2 Optimized)
- Comprehensive file system scanning and analysis
- Real-time security risk assessment and monitoring
- Detailed vulnerability reporting with mitigation recommendations
- Continuous monitoring capabilities
- M2 chip optimized for performance

## Tech Stack
- Python 3.10+
- TensorFlow
- scikit-learn
- FastAPI
- Jupyter Notebooks
- JSON for intent training data

## Project Structure
```
AI-Chatbot/
├── data/
│   └── intents.json               # Sample training data (intents, responses)
├── model/
│   └── chatbot_model.h5           # Trained TensorFlow model (generated)
├── notebooks/
│   └── training.ipynb             # Notebook for training and evaluation
├── app/
│   ├── main.py                    # FastAPI app serving the chatbot
│   └── requirements.txt           # Dependencies
├── assistant/
│   ├── cli.py                     # Security assistant CLI tool
│   ├── scanner.py                 # File system scanner
│   ├── security_analyzer.py       # Security risk assessment engine
│   ├── reporter.py                # Report generation
│   └── requirements.txt           # Assistant dependencies
├── README.md
└── .gitignore
```

## Getting Started

### Chatbot Setup

1. Clone the repository
```bash
git clone https://github.com/jdgiles26/AI-Chatbot.git
cd AI-Chatbot
```

2. Create a virtual environment and install dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r app/requirements.txt
```

3. Train the model
Open `notebooks/training.ipynb` and run all cells to train and save the model.

4. Run the FastAPI server
```bash
uvicorn app.main:app --reload
```

Then visit `http://127.0.0.1:8000/docs` to test your chatbot API.

### Security Assistant Setup (Mac Mini M2)

1. Install the assistant CLI dependencies
```bash
pip install -r assistant/requirements.txt
```

2. Make the assistant executable
```bash
chmod +x assistant/cli.py
```

3. Run security scan
```bash
python3 assistant/cli.py scan --path /path/to/scan
```

4. Generate security report
```bash
python3 assistant/cli.py report --output security_report.json
```

5. Start continuous monitoring
```bash
python3 assistant/cli.py monitor --interval 300
```

## Usage

### Chatbot API
Send POST requests to `/predict` endpoint:
```json
{
  "message": "Hello"
}
```

### Security Assistant
The assistant CLI provides comprehensive security analysis:
- Scans file system for potential security risks
- Identifies suspicious files and permissions
- Monitors file changes in real-time
- Generates detailed reports with mitigation steps

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contact
For questions and support, please open an issue on GitHub.


