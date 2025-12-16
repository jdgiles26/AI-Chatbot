# AI Chatbot using NLP & TensorFlow

An intelligent chatbot built with **Python**, **TensorFlow**, and **Natural Language Processing (NLP)**. This project demonstrates how to build and deploy a simple conversational AI capable of understanding user intent and generating relevant responses.

## ✨ Features
- Intent recognition using custom-trained LSTM model
- Clean, structured NLP pipeline (tokenization, stemming, vectorization)
- FastAPI-powered backend for real-time chatbot responses
- Easy to train and customize with new intents
- Deployment-ready for Render, Hugging Face Spaces, or local Docker

## 🧠 Tech Stack
- Python 3.10+
- TensorFlow
- scikit-learn
- FastAPI
- Jupyter Notebooks
- JSON (for intent training data)

## 📁 Project Structure
```
ai-chatbot-nlp/
├── data/
│   └── intents.json               # Sample training data (intents, responses)
├── model/
│   └── chatbot_model.h5           # Trained TensorFlow model
├── notebooks/
│   └── training.ipynb             # Notebook for training and evaluation
├── app/
│   ├── main.py                    # FastAPI app serving the chatbot
│   └── requirements.txt           # Dependencies
├── README.md
└── .gitignore
```

## 🚀 Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/Zig-Tutorials/ai-chatbot-nlp.git
cd ai-chatbot-nlp
```

### 2. Create a virtual environment and install dependencies
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r app/requirements.txt
```

### 3. Train the model
Open `notebooks/training.ipynb` and run all cells to train and save the model.

### 4. Run the FastAPI server
```bash
uvicorn app.main:app --reload
```

Then go to `http://127.0.0.1:8000/docs` to test your chatbot API.

## 📄 License
This project is licensed under the MIT License. See the LICENSE file for details.

## 📬 Contact
**DCorey Zeigler** – [LinkedIn](https://linkedin.com/in/d-corey-zeigler-b55472a4) | [GitHub](https://github.com/Zig-Tutorials)

---

> 🚧 Project is a work in progress — improvements and pull requests welcome!


