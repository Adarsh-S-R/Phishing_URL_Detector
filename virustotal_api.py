import requests
import time
import base64
import json

DEFAULT_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

def check_virustotal(url, api_key=None):
    # Check if a URL is malicious using VirusTotal API v3
    # Use the default API key if none is provided
    if not api_key:
        api_key = DEFAULT_API_KEY

    try:
    # Try to use the VirusTotal API
        return _check_virustotal_api(url, api_key)
    except Exception as e:
        error_message = str(e)

    # Check if this is a common API issue
        is_api_issue = any(phrase in error_message.lower() for phrase in [
            "rate limit", "quota", "timeout", "connection", "network", "unavailable", "unauthorized"
        ])

    # Fallback response
        return {
            'is_phishing': False,  # Default to safe
            'positives': 0,
            'total': 0,
            'scan_date': None,
            'permalink': None,
            'error': error_message,
            'using_fallback': True,
            'api_issue': is_api_issue,
            'checked_url': url
        }

def _check_virustotal_api(url, api_key):
    # Internal function to check the VirusTotal API v3
    # Base64 encode the URL as required by the API v3
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')

    # Set up the headers with the API key
    headers = {
        'x-apikey': api_key,
        'accept': 'application/json',
        'content-type': 'application/x-www-form-urlencoded'
    }

    # First, try to get the analysis if it exists
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        # Get the URL analysis if it exists
        response = requests.get(analysis_url, headers=headers)

        # If the URL hasn't been analyzed yet (404) or analysis is too old, submit it
        if response.status_code == 404 or (response.status_code == 200 and
                                          _is_analysis_too_old(response.json())):
            # Submit the URL for analysis
            return _submit_url_for_analysis(url, url_id, headers)

        # If we got a successful response, process it
        elif response.status_code == 200:
            return _process_analysis_response(response.json(), url)

        # Handle other error codes
        else:
            raise Exception(f"VirusTotal API returned status code {response.status_code}: {response.text}")

    except requests.exceptions.RequestException as e:
        raise Exception(f"Error connecting to VirusTotal API: {str(e)}")

def _is_analysis_too_old(data):
    # Check if the analysis is older than 1 day
    try:
        # Get the last analysis date
        last_analysis_date = data.get('data', {}).get('attributes', {}).get('last_analysis_date')
        if last_analysis_date:
            # Check if it's older than 1 day (86400 seconds)
            return (time.time() - last_analysis_date) > 86400
    except (KeyError, TypeError):
        pass

    # If we can't determine the age, assume it's too old
    return True

def _submit_url_for_analysis(url, url_id, headers):
    # Submit a URL for analysis and get the results
    # Submit URL for analysis
    submit_url = "https://www.virustotal.com/api/v3/urls"
    data = f"url={url}"

    try:
        # Submit the URL
        submit_response = requests.post(submit_url, data=data, headers=headers)

        # Check for errors
        if submit_response.status_code != 200:
            raise Exception(f"VirusTotal API scan returned status code {submit_response.status_code}: {submit_response.text}")

        # Get the analysis ID
        analysis_id = submit_response.json().get('data', {}).get('id')
        if not analysis_id:
            raise Exception("Failed to get analysis ID from VirusTotal API")

        # Wait for the analysis to complete (up to 30 seconds)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(6):  # Try 6 times with 5 second intervals
            time.sleep(5)

            # Check the analysis status
            analysis_response = requests.get(analysis_url, headers=headers)

            if analysis_response.status_code == 200:
                status = analysis_response.json().get('data', {}).get('attributes', {}).get('status')
                if status == 'completed':
                    # Analysis is complete, get the URL report
                    url_report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                    report_response = requests.get(url_report_url, headers=headers)

                    if report_response.status_code == 200:
                        return _process_analysis_response(report_response.json(), url)

        # If we get here, the analysis didn't complete in time
        raise Exception("VirusTotal analysis did not complete in the allotted time")

    except requests.exceptions.RequestException as e:
        raise Exception(f"Error submitting URL to VirusTotal: {str(e)}")

def _process_analysis_response(data, original_url):
    # Process the analysis response from VirusTotal API
    try:
        # Extract the relevant information
        attributes = data.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        last_analysis_results = attributes.get('last_analysis_results', {})

        # Count the number of engines that detected it as malicious
        malicious = last_analysis_stats.get('malicious', 0)
        suspicious = last_analysis_stats.get('suspicious', 0)
        total = sum(last_analysis_stats.values())
        positives = malicious + suspicious

        # Consider it phishing if at least 2 engines detect it as malicious or suspicious
        is_phishing = positives >= 2

        # Get the permalink
        permalink = f"https://www.virustotal.com/gui/url/{base64.urlsafe_b64encode(original_url.encode()).decode().strip('=')}/detection"

        # Get the scan date
        scan_date = attributes.get('last_analysis_date')
        if scan_date:
            scan_date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(scan_date))

        # Prepare the results
        results = {
            'is_phishing': is_phishing,
            'positives': positives,
            'total': total,
            'scan_date': scan_date,
            'permalink': permalink,
            'using_fallback': False,
            'categories': attributes.get('categories', {}),
            'reputation': attributes.get('reputation', 0)
        }

        # Add detailed scan results (limited to avoid too much data)
        scan_details = {}
        for engine, result in last_analysis_results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                scan_details[engine] = {
                    'category': result.get('category'),
                    'result': result.get('result')
                }

        if scan_details:
            results['scan_details'] = scan_details

        return results

    except (KeyError, TypeError) as e:
        raise Exception(f"Error processing VirusTotal response: {str(e)}")
