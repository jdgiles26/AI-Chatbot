# Import FastAPI and other necessary libraries
from fastapi import FastAPI, HTTPException  # FastAPI to build the API, HTTPException for error handling
from pydantic import BaseModel            # Pydantic for request validation
import uvicorn                           # Uvicorn to run the app
import json                              # To load JSON data (intents)
import numpy as np                       # For numerical operations (e.g., argmax)
import tensorflow as tf                  # TensorFlow for loading and using the trained model
from tensorflow.keras.preprocessing.sequence import pad_sequences  # For padding sequences
import pickle                            # To load the tokenizer and label encoder
import random                            # For selecting a random response
import os                                # For constructing file paths

# Create an instance of FastAPI
app = FastAPI(
    title="AI Chatbot API",
    description="An API for an AI-powered chatbot using TensorFlow and NLP.",
    version="1.0"
)

# Define a Pydantic model for the expected request body.
class ChatbotRequest(BaseModel):
    message: str  # The user's input message

# Build file paths relative to the current file's directory.
# __file__ is the current file's path, and os.path.join constructs paths for different folders.

# Load the trained TensorFlow model from the model directory
model_path = os.path.join(os.path.dirname(__file__), "../model/chatbot_model.h5")
model = tf.keras.models.load_model(model_path)

# Load the tokenizer used during training (stored as a pickle file)
tokenizer_path = os.path.join(os.path.dirname(__file__), "../model/tokenizer.pickle")
with open(tokenizer_path, "rb") as handle:
    tokenizer = pickle.load(handle)

# Load the label encoder used during training (stored as a pickle file)
label_encoder_path = os.path.join(os.path.dirname(__file__), "../model/label_encoder.pickle")
with open(label_encoder_path, "rb") as enc_file:
    label_encoder = pickle.load(enc_file)

# Load the intents JSON file which contains the training data and responses
intents_path = os.path.join(os.path.dirname(__file__), "../data/intents.json")
with open(intents_path) as f:
    intents = json.load(f)

# Define a helper function to compute the maximum sequence length from the training data
def get_max_length():
    """
    Calculates the maximum sequence length based on the training patterns from intents.
    This ensures that new user input is padded to the same length as the training data.
    """
    patterns = []  # List to store all training patterns
    for intent in intents['intents']:
        for pattern in intent['patterns']:
            patterns.append(pattern)
    # Convert patterns to sequences using the trained tokenizer
    sequences = tokenizer.texts_to_sequences(patterns)
    # Determine the maximum length among all sequences
    max_length = max(len(seq) for seq in sequences)
    return max_length

# Compute the maximum sequence length to be used for padding new messages
max_length = get_max_length()

# Define a root endpoint that returns a simple welcome message.
@app.get("/")
def read_root():
    """
    Root endpoint that returns a welcome message.
    """
    return {"message": "Welcome to the AI Chatbot API. Use the /predict endpoint to get a response from the chatbot."}

# Define the prediction endpoint that accepts a JSON payload with the user's message.
@app.post("/predict")
def predict(request: ChatbotRequest):
    """
    Endpoint to predict the chatbot response.
    
    - Receives a JSON payload with a 'message' key.
    - Processes the message to predict an intent.
    - Selects and returns a random response based on the predicted intent.
    """
    # Retrieve the user's message from the request object
    user_message = request.message

    # Convert the input message into a sequence of integers using the tokenizer.
    sequence = tokenizer.texts_to_sequences([user_message])
    
    # Pad the sequence to ensure it matches the maximum sequence length from training.
    padded_sequence = pad_sequences(sequence, maxlen=max_length, padding='post')

    # Use the loaded model to predict the intent probabilities for the input message.
    prediction = model.predict(padded_sequence)
    
    # Identify the index of the highest probability (i.e., the predicted intent)
    predicted_index = np.argmax(prediction)
    
    # Convert the index back to the corresponding tag (intent label)
    predicted_tag = label_encoder.inverse_transform([predicted_index])[0]

    # Search for the predicted tag in the intents data to retrieve associated responses.
    for intent in intents['intents']:
        if intent['tag'] == predicted_tag:
            responses = intent['responses']
            break
    else:
        # If the predicted tag is not found, return an error.
        raise HTTPException(status_code=404, detail="Intent not found")

    # Randomly choose one of the responses to return to the user.
    bot_response = random.choice(responses)

    # Return the predicted intent and the chatbot's response in JSON format.
    return {"intent": predicted_tag, "response": bot_response}

# If this script is run directly, use uvicorn to serve the FastAPI app.
if __name__ == "__main__":
    # Runs the app on host 0.0.0.0 and port 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)