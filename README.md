
<p align="center">
  <img src="assets/image.png" alt="Phishing Detection" style="width:100%;"/>
</p>

# Phishing URL Detector

A Flask web application to check if a URL is suspicious by querying PhishTank and VirusTotal, plus a quick local blacklist check.

## Features
- Instantly flags URLs found in a local blacklist
- Can query PhishTank and VirusTotal for phishing reports
- Lets you add URLs to your own blacklist
- Falls back if APIs are down or rate-limited

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

## Security
This repository contains no real API keys.  
`virustotal_api.py` includes only a placeholder key (`YOUR_VIRUSTOTAL_API_KEY`).  
Keep your actual keys private and out of version control.  

The local URL blacklist is saved in `blacklist.json`.

## Notes
- Free VirusTotal API keys are limited to 4 requests/minute.
- PhishTank API may have daily limits and reliability issues; the app handles these gracefully.

