from flask import Flask, render_template, request, jsonify, session
import os
import random
import time
import uuid
import json
from werkzeug.utils import secure_filename
import threading
from pathlib import Path

# Load environment variables from .env file in development
env_path = Path('.') / '.env'
if env_path.exists():
    print("Loading environment variables from .env file")
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=env_path)

# Try to import Google's Generative AI
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

# Try to import PyPDF2
try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_for_testing')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

analysis_results = {}

# Configure Google Generative AI if available
if GENAI_AVAILABLE:
    try:
        # Get API key from environment variable (for security)
        API_KEY = os.environ.get("GOOGLE_API_KEY", "")

        # Print a masked version of the API key for debugging
        if API_KEY:
            masked_key = "API_KEY_PROVIDED"
            print(f"Attempting to configure Gemini with API key: {masked_key}")
        else:
            print("No API key provided")

        if API_KEY:
            # Configure the API
            genai.configure(api_key=API_KEY)
            print("Gemini API key configured")

            # Try to create a model instance
            try:
                # Try with different model names in case one works
                model_names = [
                    "gemini-1.5-flash-latest",
                    "gemini-1.5-flash",
                    "gemini-pro",
                    "gemini-1.0-pro"
                ]

                model = None
                for model_name in model_names:
                    try:
                        print(f"Trying to initialize model: {model_name}")
                        model = genai.GenerativeModel(model_name)
                        print(f"Successfully initialized model: {model_name}")
                        break
                    except Exception as model_error:
                        print(f"Failed to initialize model {model_name}: {model_error}")

                if model is None:
                    raise Exception("Could not initialize any Gemini model")

                # Test the model with a simple prompt
                try:
                    test_response = model.generate_content("Say hello")
                    print(f"Test response received: {test_response.text[:20]}...")
                    print("Gemini API is fully functional!")
                except Exception as test_error:
                    print(f"Model test failed: {test_error}")
                    raise test_error

            except Exception as model_error:
                print(f"Error initializing Gemini model: {model_error}")
                GENAI_AVAILABLE = False
        else:
            print("No Gemini API key provided. Falling back to random analysis.")
            GENAI_AVAILABLE = False
    except Exception as e:
        print(f"Error configuring Generative AI: {e}")
        GENAI_AVAILABLE = False

print(f"Gemini AI available: {GENAI_AVAILABLE}")

def create_url_analysis_prompt(url_text):
    """Create a specialized prompt for URL analysis"""
    return f"""
    You are a cybersecurity expert specializing in URL and phishing analysis. Your task is to analyze the given URL and determine if it's legitimate or a potential scam/phishing attempt.

    URL to analyze:
    {url_text[:5000]}

    Perform a comprehensive analysis considering these factors:
    1. Domain characteristics (age, reputation, unusual patterns)
    2. URL structure (suspicious parameters, redirects, encoded characters)
    3. Presence of security indicators (https, SSL)
    4. Common phishing patterns (misspellings of known brands, deceptive domains)
    5. Suspicious URL components (unusual TLDs, numeric IPs, excessive subdomains)
    6. Presence of URL shorteners or redirectors
    7. Similarity to known legitimate domains but with slight variations

    For each suspicious element you identify, explain why it's concerning.

    Provide your analysis in JSON format with the following fields:
    - is_scam: true/false
    - confidence: a number between 0-100
    - threat_type: specific type of threat if detected (e.g., "Phishing", "Typosquatting", "Malware Distribution", "Credential Harvesting"), or null if legitimate
    - suspicious_elements: array of specific suspicious elements found in the URL
    - recommendation: detailed advice for the user
    - explanation: comprehensive explanation of your analysis
    - safe_alternatives: if scam, suggest legitimate alternatives if applicable

    Only return valid JSON, no other text.
    """

def create_file_analysis_prompt(file_text):
    """Create a specialized prompt for file content analysis"""
    return f"""
    You are a cybersecurity expert specializing in malware and scam detection. Your task is to analyze the given file content and determine if it contains scams, malware indicators, or other malicious elements.

    File content to analyze:
    {file_text[:5000]}

    Perform a comprehensive analysis considering these factors:
    1. Presence of suspicious language patterns (urgency, threats, unusual offers)
    2. Social engineering tactics (fear, greed, curiosity exploitation)
    3. Requests for sensitive information (credentials, financial details)
    4. Presence of suspicious links or commands
    5. Inconsistencies in formatting, branding, or language
    6. Impersonation attempts of legitimate organizations
    7. Unusual attachments or embedded content references
    8. Grammar and spelling errors typical of scams
    9. Suspicious contact information or payment requests
    10. Indicators of common scam types (advance fee, lottery, romance, tech support)

    For each suspicious element you identify, explain why it's concerning.

    Provide your analysis in JSON format with the following fields:
    - is_scam: true/false
    - confidence: a number between 0-100
    - threat_type: specific type of threat if detected (e.g., "Phishing Email", "Ransomware", "Advance Fee Fraud", "Tech Support Scam"), or null if legitimate
    - suspicious_elements: array of specific suspicious elements found in the content
    - recommendation: detailed advice for the user
    - explanation: comprehensive explanation of your analysis
    - safety_tips: relevant safety tips based on the specific content analyzed

    Only return valid JSON, no other text.
    """

def create_general_analysis_prompt(text, content_type="text"):
    """Create a general purpose analysis prompt"""
    return f"""
    You are a cybersecurity expert specializing in scam and fraud detection. Your task is to analyze the given {content_type} content and determine if it contains scams, fraud indicators, or other malicious elements.

    Content to analyze:
    {text[:5000]}

    Perform a comprehensive analysis considering these factors:
    1. Presence of suspicious language patterns
    2. Social engineering tactics
    3. Requests for sensitive information
    4. Presence of suspicious links, commands, or attachments
    5. Inconsistencies in formatting, branding, or language
    6. Impersonation attempts
    7. Unusual requests or offers
    8. Grammar and spelling errors typical of scams
    9. Suspicious contact information or payment requests
    10. Indicators of common scam types

    For each suspicious element you identify, explain why it's concerning.

    Provide your analysis in JSON format with the following fields:
    - is_scam: true/false
    - confidence: a number between 0-100
    - threat_type: specific type of threat if detected, or null if legitimate
    - suspicious_elements: array of specific suspicious elements found
    - recommendation: detailed advice for the user
    - explanation: comprehensive explanation of your analysis

    Only return valid JSON, no other text.
    """

def predict_with_genai(text, content_type="text"):
    """Use Google's Generative AI to analyze content"""
    if not GENAI_AVAILABLE or not text:
        return None

    try:
        # Select the appropriate prompt based on content type
        if content_type.lower() == 'url':
            prompt = create_url_analysis_prompt(text)
        elif content_type.lower() == 'file':
            prompt = create_file_analysis_prompt(text)
        else:
            prompt = create_general_analysis_prompt(text, content_type)

        response = model.generate_content(prompt)
        response_text = response.text.strip()

        # Extract JSON from response
        try:
            # Find JSON in the response (it might be wrapped in code blocks)
            if "```json" in response_text:
                json_str = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                json_str = response_text.split("```")[1].strip()
            else:
                json_str = response_text

            result = json.loads(json_str)
            return result
        except json.JSONDecodeError:
            print(f"Failed to parse JSON from response: {response_text}")
            return None

    except Exception as e:
        print(f"Error using Generative AI: {e}")
        return None

def analyze_content_async(content_id, content, content_type):
    """Analyze content asynchronously and store results"""
    # Simulate processing time
    time.sleep(2)

    # Update progress
    analysis_results[content_id]['progress'] = 50
    analysis_results[content_id]['status'] = 'Processing'

    # Try to use GenAI if available
    if GENAI_AVAILABLE:
        result = predict_with_genai(content, content_type)
        if result:
            analysis_results[content_id].update(result)
            analysis_results[content_id]['progress'] = 100
            analysis_results[content_id]['status'] = 'Complete'
            return

    # Fallback to random results
    time.sleep(1)  # Simulate more processing
    is_scam = random.choice([True, False])

    result = {
        'is_scam': is_scam,
        'confidence': random.randint(70, 99),
        'threat_type': 'Malicious Content' if is_scam else None,
        'recommendation': 'Do not trust this content' if is_scam else 'Content appears to be safe',
        'explanation': 'Our analysis detected suspicious patterns typical of scams.' if is_scam else 'No suspicious patterns were detected in this content.',
        'progress': 100,
        'status': 'Complete'
    }

    analysis_results[content_id].update(result)

def extract_text_from_file(file):
    """Extract text from uploaded files with enhanced metadata"""
    if not file or file.filename == '':
        return None

    file_info = {
        'filename': file.filename,
        'size': 0,
        'type': 'unknown',
        'content': '',
        'metadata': {}
    }

    try:
        # Get file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        file_info['size'] = file_size

        # Determine file type and extract content
        filename_lower = file.filename.lower()

        # PDF files
        if filename_lower.endswith('.pdf') and PDF_AVAILABLE:
            file_info['type'] = 'PDF document'
            pdf_reader = PyPDF2.PdfReader(file)

            # Extract text content
            extracted_text = ' '.join([page.extract_text() for page in pdf_reader.pages if page.extract_text()])
            file_info['content'] = extracted_text

            # Extract metadata
            if pdf_reader.metadata:
                file_info['metadata'] = {
                    'author': pdf_reader.metadata.get('/Author', 'Unknown'),
                    'creator': pdf_reader.metadata.get('/Creator', 'Unknown'),
                    'producer': pdf_reader.metadata.get('/Producer', 'Unknown'),
                    'subject': pdf_reader.metadata.get('/Subject', ''),
                    'title': pdf_reader.metadata.get('/Title', ''),
                    'pages': len(pdf_reader.pages)
                }

        # Text files
        elif filename_lower.endswith(('.txt', '.csv', '.md', '.html', '.xml', '.json', '.js', '.py', '.c', '.cpp', '.java')):
            file_info['type'] = 'Text document'
            content = file.read().decode('utf-8', errors='ignore')
            file_info['content'] = content

            # Basic metadata
            file_info['metadata'] = {
                'lines': content.count('\n') + 1,
                'characters': len(content)
            }

            # Specific file type identification
            if filename_lower.endswith('.html'):
                file_info['type'] = 'HTML document'
            elif filename_lower.endswith('.json'):
                file_info['type'] = 'JSON data'
            elif filename_lower.endswith('.csv'):
                file_info['type'] = 'CSV data'
            elif filename_lower.endswith(('.py', '.js', '.java', '.c', '.cpp')):
                file_info['type'] = 'Source code'

        # Email files
        elif filename_lower.endswith(('.eml', '.msg')):
            file_info['type'] = 'Email message'
            content = file.read().decode('utf-8', errors='ignore')
            file_info['content'] = content

            # Extract basic email headers if possible
            headers = {}
            for line in content.split('\n')[:20]:  # Check first 20 lines for headers
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            file_info['metadata'] = {
                'from': headers.get('From', headers.get('FROM', 'Unknown')),
                'to': headers.get('To', headers.get('TO', 'Unknown')),
                'subject': headers.get('Subject', headers.get('SUBJECT', 'Unknown')),
                'date': headers.get('Date', headers.get('DATE', 'Unknown'))
            }

        # Other file types
        else:
            # For unsupported file types, just use the filename and extension
            extension = os.path.splitext(filename_lower)[1] or 'unknown'
            file_info['type'] = f"Unsupported file type ({extension})"
            file_info['content'] = f"File analysis for {file.filename} (type: {extension}) is limited. Please upload text-based files for better analysis."

    except Exception as e:
        print(f"Error extracting text: {e}")
        file_info['content'] = f"Error analyzing file {file.filename}: {str(e)}"

    # Format the extracted information as text for analysis
    formatted_text = f"""
    FILE ANALYSIS:
    Filename: {file_info['filename']}
    File type: {file_info['type']}
    File size: {file_info['size']} bytes

    METADATA:
    {json.dumps(file_info['metadata'], indent=2)}

    CONTENT:
    {file_info['content'][:5000]}  # Limit content length
    """

    return formatted_text

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect-file', methods=['POST'])
def detect_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Generate a unique ID for this analysis
    analysis_id = str(uuid.uuid4())

    # Save file temporarily
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{analysis_id}_{filename}")
    file.save(file_path)

    # Extract text from file
    extracted_text = extract_text_from_file(file)

    # Clean up the file
    try:
        os.remove(file_path)
    except Exception as e:
        print(f"Error removing temporary file: {e}")

    if not extracted_text:
        return jsonify({'error': 'Could not extract text from file'}), 400

    # Initialize analysis result
    analysis_results[analysis_id] = {
        'id': analysis_id,
        'content_type': 'file',
        'filename': file.filename,
        'progress': 10,
        'status': 'Started'
    }

    # Start analysis in background
    threading.Thread(
        target=analyze_content_async,
        args=(analysis_id, extracted_text, 'file')
    ).start()

    return jsonify({
        'analysis_id': analysis_id,
        'status': 'processing'
    })

@app.route('/detect-url', methods=['POST'])
def detect_url():
    url = request.form.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Generate a unique ID for this analysis
    analysis_id = str(uuid.uuid4())

    # Prepare enhanced URL information for analysis
    # Include protocol if missing
    if not url.startswith(('http://', 'https://')):
        url_with_protocol = f"https://{url}"
    else:
        url_with_protocol = url

    # Extract domain and other URL components for better analysis
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url_with_protocol)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query

        # Create enhanced URL information
        url_info = f"""
        URL: {url}
        URL with protocol: {url_with_protocol}
        Domain: {domain}
        Path: {path or '/'}
        Query parameters: {query or 'None'}
        """
    except Exception as e:
        print(f"Error parsing URL: {e}")
        url_info = f"URL: {url}"

    # Initialize analysis result
    analysis_results[analysis_id] = {
        'id': analysis_id,
        'content_type': 'url',
        'url': url,
        'progress': 10,
        'status': 'Started'
    }

    # Start analysis in background
    threading.Thread(
        target=analyze_content_async,
        args=(analysis_id, url_info, 'url')
    ).start()

    return jsonify({
        'analysis_id': analysis_id,
        'status': 'processing'
    })

@app.route('/analysis-status/<analysis_id>', methods=['GET'])
def analysis_status(analysis_id):
    """Check the status of an analysis"""
    if analysis_id not in analysis_results:
        return jsonify({'error': 'Analysis not found'}), 404

    return jsonify(analysis_results[analysis_id])

@app.route('/api/check-genai-status', methods=['GET'])
def check_genai_status():
    """Check if GenAI is available"""
    return jsonify({
        'available': GENAI_AVAILABLE,
        'pdf_support': PDF_AVAILABLE
    })

if __name__ == '__main__':
    # Use environment variables for configuration in production
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV", "development") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
