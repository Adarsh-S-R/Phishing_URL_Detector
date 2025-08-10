import requests
import urllib.parse
import time
import re
import xml.etree.ElementTree as ET
import json
import base64

def check_phishtank(url, api_key=None):
    """
    Check if a URL is a phishing site using PhishTank API.
    Works with or without an API key.

    Args:
        url (str): The URL to check
        api_key (str, optional): PhishTank API key. Default is None.

    Returns:
        dict: Results with is_phishing and other details
    """
    # Due to issues with the PhishTank API, we're implementing a fallback mechanism
    # that returns a default response when the API is not working correctly

    try:
        # Try to use the PhishTank API
        return _check_phishtank_api(url, api_key)
    except Exception as e:
        error_message = str(e)
        print(f"PhishTank API error: {error_message}")
        print("Using fallback mechanism...")

        # Check if this is a common API issue
        is_api_issue = any(phrase in error_message.lower() for phrase in [
            "not accepting", "parameter", "rate limit", "timeout",
            "connection", "network", "unavailable"
        ])

        # Fallback: Return a default response
        # This is a very basic check - in a real application, you would want to implement
        # more sophisticated checks or use a local database
        return {
            'is_phishing': False,  # Default to safe
            'verified': False,
            'phish_id': None,
            'phish_detail_page': None,
            'submitted_at': None,
            'error': error_message,
            'using_fallback': True,
            'api_issue': is_api_issue,  # Flag to indicate if this is a known API issue
            'checked_url': url  # Include the URL that was checked
        }

def _check_phishtank_api(url, api_key=None):
    """
    Internal function to check the PhishTank API.
    """
    # Use the HTTPS version of the API with JSON format
    API_URL = 'https://checkurl.phishtank.com/checkurl/'

    # Set headers with a descriptive User-Agent
    headers = {
        'User-Agent': 'phishtank/phishing_detection_app',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Base64 encode the URL as required by the API
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip('=')

    # Prepare the data payload
    post_data = {
        'url': encoded_url,
        'format': 'json',  # Use JSON format based on our tests
        'encoding': 'base64'  # Specify that we're using base64 encoding
    }

    if api_key:
        post_data['app_key'] = api_key

    max_retries = 2
    retry_count = 0

    while retry_count < max_retries:
        try:
            # Print debug information
            print(f"PhishTank API request - URL: {API_URL}")
            print(f"PhishTank API request - Headers: {headers}")
            print(f"PhishTank API request - Data: {post_data}")
            print(f"PhishTank API request - Original URL: {url}")
            print(f"PhishTank API request - Base64 URL: {encoded_url}")

            # Make the request
            response = requests.post(API_URL, data=post_data, headers=headers)

            # Print response information
            print(f"PhishTank API response - Status: {response.status_code}")
            print(f"PhishTank API response - Headers: {response.headers}")
            print(f"PhishTank API response - Content (first 200 chars): {response.text[:200]}...")

            # Check for rate limiting
            if response.status_code == 509:
                limit = response.headers.get('X-Request-Limit', '30')
                count = response.headers.get('X-Request-Count', '30')
                interval = response.headers.get('X-Request-Limit-Interval', '300 Seconds')

                if retry_count < max_retries - 1:
                    retry_count += 1
                    time.sleep(min(int(interval.split()[0]) / 2, 30) if interval else 30)
                    continue
                else:
                    raise Exception(f"Rate limited by PhishTank API")

            # Handle other error status codes
            if response.status_code != 200:
                raise Exception(f"PhishTank API returned status code {response.status_code}")

            # Check for common error messages in the response
            if "You must supply a URL to use this function" in response.text:
                raise Exception("PhishTank API error: API is not accepting the URL parameter correctly. This is a known issue with the PhishTank API.")

            # Check for other potential error messages
            if "errortext" in response.text.lower():
                import re
                error_match = re.search(r'<errortext>(.*?)</errortext>', response.text)
                if error_match:
                    error_text = error_match.group(1)
                    raise Exception(f"PhishTank API error: {error_text}")

            # Parse the JSON response
            try:
                # Try to parse as JSON
                data = response.json()

                # Check for error in the response
                if data.get('meta', {}).get('status') == 'error':
                    error_msg = data.get('errortext', 'Unknown error')
                    raise Exception(f"PhishTank API error: {error_msg}")

                # Extract results
                results = data.get('results', {})

                # Get the values
                in_database = results.get('in_database', False)
                verified = results.get('verified', False) == 'y' or results.get('verified', False) is True
                phish_id = results.get('phish_id')
                phish_detail_page = results.get('phish_detail_page')
                submitted_at = results.get('submitted_at')

                return {
                    'is_phishing': in_database,
                    'verified': verified,
                    'phish_id': phish_id,
                    'phish_detail_page': phish_detail_page,
                    'submitted_at': submitted_at
                }

            except ValueError as e:
                # If JSON parsing fails, try XML as fallback
                try:
                    # Try to parse as XML
                    root = ET.fromstring(response.text)

                    # Check for error text
                    error_elem = root.find('.//errortext')
                    if error_elem is not None and error_elem.text:
                        raise Exception(f"PhishTank API error: {error_elem.text}")

                    # Extract results
                    in_database = False
                    verified = False
                    phish_id = None
                    phish_detail_page = None
                    submitted_at = None

                    # Look for results in the XML
                    url_elem = root.find('.//url0') or root.find('.//results')
                    if url_elem is not None:
                        in_database_elem = url_elem.find('in_database')
                        if in_database_elem is not None:
                            in_database = in_database_elem.text.lower() == 'true'

                        verified_elem = url_elem.find('verified')
                        if verified_elem is not None:
                            verified = verified_elem.text.lower() == 'true' or verified_elem.text == 'y'

                        phish_id_elem = url_elem.find('phish_id')
                        if phish_id_elem is not None:
                            phish_id = phish_id_elem.text

                        phish_detail_page_elem = url_elem.find('phish_detail_page')
                        if phish_detail_page_elem is not None:
                            phish_detail_page = phish_detail_page_elem.text

                        submitted_at_elem = url_elem.find('submitted_at')
                        if submitted_at_elem is not None:
                            submitted_at = submitted_at_elem.text

                    return {
                        'is_phishing': in_database,
                        'verified': verified,
                        'phish_id': phish_id,
                        'phish_detail_page': phish_detail_page,
                        'submitted_at': submitted_at
                    }

                except ET.ParseError as e:
                    raise Exception(f"Failed to parse PhishTank API response: {str(e)}")

        except Exception as e:
            if retry_count < max_retries - 1:
                retry_count += 1
                time.sleep(2)
            else:
                raise

    raise Exception("Unexpected error in PhishTank API request")