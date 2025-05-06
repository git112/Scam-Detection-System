# Scam Detection System

A web application that uses AI to detect potential scams in files and URLs.

## Features

- File analysis for detecting scams in documents
- URL verification to identify phishing and malicious websites
- Real-time analysis with progress tracking
- Powered by Google's Generative AI (Gemini)
- Detailed threat analysis with recommendations

## Technologies Used

- Python Flask for the backend
- HTML, CSS, and JavaScript for the frontend
- Google Generative AI for scam detection
- PyPDF2 for PDF file analysis

## Setup and Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Edit `.env` and add your Google API key:
     ```
     GOOGLE_API_KEY=your_api_key_here
     FLASK_ENV=development
     PORT=5000
     ```
4. Run the application:
   ```
   python main.py
   ```

> **IMPORTANT**: Never commit your `.env` file or expose your API keys in your code. The `.env` file is included in `.gitignore` to prevent accidental commits.

## Environment Variables

- `GOOGLE_API_KEY`: Your Google Generative AI API key
- `FLASK_ENV`: Set to "development" for debug mode, "production" for production
- `PORT`: Port number (default: 5000)

## Deployment

This application is deployed on Render.

## License

MIT
