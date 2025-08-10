from flask import Flask, render_template, request, jsonify
import json
import os
from phishtank_api import check_phishtank
from virustotal_api import check_virustotal

# Get VirusTotal API key from environment variable or use the default one in virustotal_api.py
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

app = Flask(__name__)

def load_blacklist():
    try:
        with open('blacklist.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {'urls': []}

def save_to_blacklist(url):
    blacklist = load_blacklist()
    if url not in blacklist['urls']:
        blacklist['urls'].append(url)
        with open('blacklist.json', 'w') as f:
            json.dump(blacklist, f, indent=4)
        return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Check local blacklist first
    blacklist = load_blacklist()
    if url in blacklist['urls']:
        return jsonify({'status': 'phishing', 'source': 'blacklist'})

    # Results from both APIs
    results = {
        'phishtank': None,
        'virustotal': None
    }

    # Check PhishTank API
    phishtank_is_phishing = False
    try:
        phishtank_result = check_phishtank(url)
        results['phishtank'] = phishtank_result

        # Check if PhishTank identifies it as phishing
        if phishtank_result.get('is_phishing', False):
            phishtank_is_phishing = True
            # Add to blacklist
            save_to_blacklist(url)
    except Exception as e:
        results['phishtank'] = {
            'error': str(e),
            'using_fallback': True
        }

    # Check VirusTotal API
    virustotal_is_phishing = False
    try:
        virustotal_result = check_virustotal(url, VIRUSTOTAL_API_KEY)
        results['virustotal'] = virustotal_result

        # Check if VirusTotal identifies it as phishing
        if virustotal_result.get('is_phishing', False):
            virustotal_is_phishing = True
            # Add to blacklist
            save_to_blacklist(url)
    except Exception as e:
        results['virustotal'] = {
            'error': str(e),
            'using_fallback': True
        }

    # Check if either API identified the URL as phishing
    is_phishing = phishtank_is_phishing or virustotal_is_phishing

    if is_phishing:
        # Determine the primary source (which API identified it as phishing)
        primary_source = 'phishtank' if phishtank_is_phishing else 'virustotal'

        # Create response for phishing URL
        phishing_response = {
            'status': 'phishing',
            'source': primary_source,
            'api_results': {
                'phishtank_checked': not results['phishtank'].get('using_fallback', False),
                'virustotal_checked': not results['virustotal'].get('using_fallback', False),
                'phishtank_detected': phishtank_is_phishing,
                'virustotal_detected': virustotal_is_phishing
            },
            'details': {
                'phishtank': results['phishtank'],
                'virustotal': results['virustotal']
            }
        }
        return jsonify(phishing_response)

    # If both APIs failed or used fallback
    if (results['phishtank'].get('using_fallback', False) and
        results['virustotal'].get('using_fallback', False)):
        # Create response data dictionary
        response_data = {
            'status': 'unknown',
            'message': 'Unable to check with any API. Using local checks only.',
            'checked_url': url,
            'api_results': {
                'phishtank_checked': not results['phishtank'].get('using_fallback', False),
                'virustotal_checked': not results['virustotal'].get('using_fallback', False)
            },
            'details': {
                'phishtank': results['phishtank'],
                'virustotal': results['virustotal']
            }
        }

        # Add more context if these are known API issues
        if results['phishtank'].get('api_issue', False) or results['virustotal'].get('api_issue', False):
            response_data['api_issue'] = True
            response_data['message'] = 'The APIs are currently experiencing issues. This is common and doesn\'t mean the URL is safe.'

        return jsonify(response_data)

    # If we got here, both APIs say it's safe
    safe_response = {
        'status': 'safe',
        'api_results': {
            'phishtank_checked': not results['phishtank'].get('using_fallback', False),
            'virustotal_checked': not results['virustotal'].get('using_fallback', False)
        },
        'details': {
            'phishtank': results['phishtank'],
            'virustotal': results['virustotal']
        }
    }
    return jsonify(safe_response)

@app.route('/add_to_blacklist', methods=['POST'])
def add_to_blacklist():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    if save_to_blacklist(url):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'already_exists'})

if __name__ == '__main__':
    app.run(debug=True)