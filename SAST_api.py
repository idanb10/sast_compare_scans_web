#SAST_api.py

import requests
import datetime
import logging

def SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url):
    try:
        logging.info(f"SAST_api.SAST_get_access_token: Attempting to obtain access token for user '{SAST_username}'")
        payload = {
            'scope': 'access_control_api sast_api',
            'client_id': 'resource_owner_sast_client',
            'grant_type': 'password',
            'client_secret': '014DF517-39D1-4453-B7B3-9930C563627C',
            'username': SAST_username,
            'password': SAST_password
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(SAST_auth_url, headers=headers, data=payload, verify=False)
        response.raise_for_status()
        access_token = response.json()['access_token']
        logging.info("SAST_api.SAST_get_access_token: Access token obtained.")
        return access_token
    except requests.exceptions.RequestException as e:
        logging.error(f"SAST_api.SAST_get_access_token: Failed to obtain access token for user '{SAST_username}'")
        #print(f"Exception: get SAST access token failed: {e}")
        return ""

def SAST_get_projects(access_token, SAST_api_url):
    try:
        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        url = f'{SAST_api_url}/projects'

        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        
        return response.json()
    except requests.exceptions.RequestException as e:
        #print(f"Exception: SAST_get_projects: {e}")
        return ""
    
def SAST_get_project_ID(access_token, project_name, SAST_api_url):
    try:
        projects = SAST_get_projects(access_token, SAST_api_url)
        projId = next((project['id'] for project in projects if project['name'] == project_name), 0)
    except Exception as e:
        #print(f"Exception: SAST_get_project_ID: {e}")
        return ""
    return projId

    
def SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, scan_id):        
    try:
        if not scan_id:
            error_message = "SAST_api.SAST_list_scan_vulnerabilities_with_scan_id: Scan id does not exist, cannot list its vulnerabilities"
            raise Exception(error_message)
        
        logging.info(f"SAST_api.SAST_list_scan_vulnerabilities_with_scan_id: Getting the results of scan with id {scan_id}.")
        
        headers = {'Authorization': f'Bearer {access_token}'}
        
        scan_results_url = f"{SAST_api_url}/sast/scans/{scan_id}/resultsStatistics"
                
        response = requests.get(scan_results_url, headers=headers, verify=False)
        response.raise_for_status()
        scan_results = response.json()
        
        simplified_scan_results = {
            'High': scan_results.get('highSeverity', 0),
            'Medium': scan_results.get('mediumSeverity', 0),
            'Low': scan_results.get('lowSeverity', 0)
        }
        logging.info(f"Results: {simplified_scan_results}")
        
        return simplified_scan_results

    except Exception as e:
        #print(f"Exception: {e}")
        logging.warning(f"SAST_api.SAST_list_scan_vulnerabilities_with_scan_id: {e}")
        return ""            

def SAST_compare_scan_vulnerabilities(old_scan_results, new_scan_results):
    
    fixed = {
        'High': old_scan_results['High'] - new_scan_results['High'],
        'Medium': old_scan_results['Medium'] - new_scan_results['Medium'],
        'Low': old_scan_results['Low'] - new_scan_results['Low']
    }
    return fixed

def SAST_get_project_latest_scan_id(access_token, project_name, SAST_api_url):
    try:
        projId = SAST_get_project_ID(access_token, project_name, SAST_api_url)
        if projId == 0:
            return 0
        
        url = f"{SAST_api_url}/sast/scans?projectId={projId}&last=1"

        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        
        response_json = response.json()
        lastScanId = response_json[0]['id']
    except Exception as e:
        #print(f"Exception: SAST_get_project_latest_scan_id: {e}")
        return ""
    else:
        #print(f'SAST_get_project_latest_scan_id scan_id= {lastScanId}')
        return lastScanId
    
def SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, scan_date, search_direction='next'):
    try:
        logging.info(f"SAST_api.SAST_get_scan_id_by_date: Getting the id of the nearest scan on or {'after' if search_direction == 'next' else 'before'} the date: {scan_date}")
        
        scans_url = f"{SAST_api_url}/sast/scans?projectId={project_id}"
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(scans_url, headers=headers, verify=False)
        response.raise_for_status()

        project_scans = response.json()
        
        selected_scan_id = None
        selected_scan_date = None
        target_scan_date = datetime.datetime.strptime(scan_date, '%Y-%m-%d').date()
        closest_date = datetime.date.max if search_direction == 'next' else datetime.date.min

        for scan in project_scans:
            if scan.get('status', {}).get('name') != 'Finished':
                logging.info(f"Skipping scan ID {scan.get('id')} with status {scan.get('status', {}).get('name')}.")
                continue

            date_and_time = scan.get('dateAndTime')
            results_statistics = scan.get('resultsStatistics')
            if not date_and_time or not results_statistics:
                logging.info(f"Skipping scan ID {scan.get('id')} due to missing dateAndTime or resultsStatistics.")
                continue

            scan_date_time_str = date_and_time.get('startedOn')
            if scan_date_time_str:
                try:
                    try:
                        scan_date_obj = datetime.datetime.strptime(scan_date_time_str, '%Y-%m-%dT%H:%M:%S.%f').date()
                    except ValueError:
                        scan_date_obj = datetime.datetime.strptime(scan_date_time_str, '%Y-%m-%dT%H:%M:%S').date()

                    if (search_direction == 'next' and scan_date_obj >= target_scan_date and scan_date_obj < closest_date) or \
                       (search_direction == 'last' and scan_date_obj <= target_scan_date and scan_date_obj > closest_date):
                        closest_date = scan_date_obj
                        selected_scan_id = scan['id']
                        selected_scan_date = scan_date_obj

                except ValueError as e:
                    logging.warning(f"Skipping invalid date format: {scan_date_time_str} - {e}")
                    continue

        if selected_scan_id and selected_scan_date:
            return selected_scan_id, selected_scan_date
        else:
            logging.info("No suitable scan found.")
            return None, None

    except Exception as e:
        logging.error(f"SAST_api.SAST_get_scan_id_by_date: {e}")
        return None, None