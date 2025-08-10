
<p align="center">
  <img src="assets/image.png" alt="Phishing Detection" width="400"/>
</p>

# Phishing URL Detection Application

A Flask web application to check if a URL is a phishing site using PhishTank and VirusTotal APIs, with a local blacklist for fast lookups.

## Features
- Check URLs against a local blacklist
- Query PhishTank and VirusTotal APIs for phishing detection
- Add URLs to a local blacklist
- Graceful fallback if APIs are unavailable or rate-limited

## Setup

### 1. Clone the repository
```bash
git clone https://github.com/Adarsh-S-R/Phishing_URL_Detector.git
cd phishing_detector
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API Keys
- **VirusTotal**: Obtain a free API key from [virustotal.com](https://www.virustotal.com/).
- Set the API key as an environment variable:
  - **Windows (PowerShell):**
    ```powershell
    $env:VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
    ```
  - **Linux/macOS:**
    ```bash
    export VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
    ```
- Alternatively, you can edit `virustotal_api.py` and replace `YOUR_VIRUSTOTAL_API_KEY` with your key (not recommended for public repos).

### 4. Run the Application
```bash
python app.py
```
Visit [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## Security & Sensitive Information
- **No sensitive API keys are included in this repository.**
- The default VirusTotal API key in `virustotal_api.py` is a placeholder (`YOUR_VIRUSTOTAL_API_KEY`).
- Do NOT commit your real API keys to the repository.
- The local blacklist is stored in `blacklist.json`.

## Notes
- Free VirusTotal API keys are limited to 4 requests/minute.
- PhishTank API may have daily limits and reliability issues; the app handles these gracefully.

## License
MIT License
