import re
import dateutil.parser
import SAST_api
import sys
import csv
import datetime
import dateutil
import io

def SAST_compare_two_scans_by_date(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, project_name, old_scan_date, new_scan_date):
    try:
        access_token = SAST_api.SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url)
        if not access_token:
            raise Exception("Failed to obtain access token")
        
        project_id = SAST_api.SAST_get_project_ID(access_token, project_name, SAST_api_url)
        if project_id == 0:
            print(f"Project '{project_name}' does not exist under the credentials that you used to access the application.")
            raise Exception(f"Project {project_name} does not exist under your username")
        
        old_scan_id, old_scan_real_date = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, old_scan_date, search_direction='next')
        new_scan_id, new_scan_real_date = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, new_scan_date, search_direction='last')
        
        if old_scan_id == new_scan_id:
            raise Exception("The same scan cannot be used for both comparison points. Please select a different date.")
        
        if old_scan_id is None or new_scan_id is None:
            raise Exception(f"Failed to find scans for both dates for project {project_name}. Make sure you have at least two scans to compare.")
            
        old_scan_results = SAST_api.SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, old_scan_id)
        new_scan_results = SAST_api.SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, new_scan_id)
        
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date : Old scan on {old_scan_real_date} results - {old_scan_results}")
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date : New scan on {new_scan_real_date} results - {new_scan_results}")
        
        fixed_vulnerabilities = SAST_api.SAST_compare_scan_vulnerabilities(old_scan_results, new_scan_results)
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date : Fixed vulnerabilities {fixed_vulnerabilities}")
        
        return old_scan_results, new_scan_results, fixed_vulnerabilities
    
        # write_scan_results_to_csv(project_name, old_scan_date, \
        #     new_scan_date, old_scan_results, new_scan_results, fixed_vulnerabilities)
        # print(f"CSV file written successfully for project {project_name}")

    except Exception as e:
        print(f"Exception: {e}")
        return None, None, None
    
def SAST_compare_scans_across_all_projects(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, old_scan_date, new_scan_date):
    access_token = SAST_api.SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url)
    if not access_token:
        raise Exception("Failed to obtain access token")

    projects = SAST_api.SAST_get_projects(access_token, SAST_api_url)
    all_old_scan_results = {}
    all_new_scan_results = {}
    all_fixed_vulnerabilities = {}

    for project in projects:
        project_name = project['name']
        print(f"Comparing scans for project: {project_name}")
        old_scan_results, new_scan_results, fixed_vulnerabilities = SAST_compare_two_scans_by_date(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, project_name, old_scan_date, new_scan_date)

        all_old_scan_results[project_name] = old_scan_results
        all_new_scan_results[project_name] = new_scan_results
        all_fixed_vulnerabilities[project_name] = fixed_vulnerabilities

    return all_old_scan_results, all_new_scan_results, all_fixed_vulnerabilities
        
def SAST_write_scan_results_to_csv(project_name, old_scan_date, new_scan_date, old_scan_results, new_scan_results, fixed_vulnerabilities, write_headers=False):
    csv_content = io.StringIO()
    writer = csv.writer(csv_content)
    
    if write_headers:
        writer.writerow(['', 'fixed', '', '', old_scan_date, '', '', new_scan_date, '', ''])
        writer.writerow(['project', 'high', 'medium', 'low', 'high', 'medium', 'low', 'high', 'medium', 'low'])
    
    writer.writerow([project_name, fixed_vulnerabilities['High'], fixed_vulnerabilities['Medium'], fixed_vulnerabilities['Low'],
                     old_scan_results['High'], old_scan_results['Medium'], old_scan_results['Low'],
                     new_scan_results['High'], new_scan_results['Medium'], new_scan_results['Low']])
    
    return csv_content.getvalue()
    
def SAST_validate_and_parse_date(date_str):
    try:
        if not re.match(r'^\d{1,2}/\d{1,2}/\d{4}$', date_str):
            print(f"Invalid date format: {date_str}. Please use the format 'DD/MM/YYYY' or 'D/M/YYYY'.")
            return None

        day, month, year = map(int, date_str.split('/'))
        
        current_year = datetime.datetime.now().year
        if year < 1900 or year > current_year:
            print(f"Year {year} is out of the acceptable range (1900-{current_year}).")
            return None

        parsed_date = datetime.datetime(year, month, day)

        return parsed_date.date()

    except (ValueError, TypeError):
        print(f"Invalid date: {date_str}. Please provide a valid date in the format 'DD/MM/YYYY'.")
        return None