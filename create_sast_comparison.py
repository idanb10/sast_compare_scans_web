#create_sast_comparison.py

import re
import dateutil.parser
import SAST_api
import sys
import csv
import datetime
import dateutil
import io
import logging

def SAST_compare_two_scans_by_date(access_token, SAST_api_url, project_name, old_scan_date, new_scan_date):
    try:
        
        project_id = SAST_api.SAST_get_project_ID(access_token, project_name, SAST_api_url)
        if project_id == 0:
            error_message = f"Project '{project_name}' does not exist under the credentials that you used to access the application."
            logging.error(f"create_sast_comparison.SAST_compare_two_scans_by_date: {error_message}")
            print(error_message)
            raise Exception(error_message)
        
        logging.info(f"create_sast_comparison.SAST_compare_two_scans_by_date: Comparing scans for project: '{project_name}', id = {project_id}")

        print(f"create_sast_comparison.SAST_compare_two_scans_by_date: Comparing scans for project: '{project_name}'")
            
        old_scan_id, old_scan_real_date = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, old_scan_date, search_direction='next')
        new_scan_id, new_scan_real_date = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, new_scan_date, search_direction='last')
        
        logging.info(f"create_sast_comparison.SAST_compare_two_scans_by_date:\nOld scan (closest to {old_scan_date}): date = {old_scan_real_date}, id = {old_scan_id}.\nNew scan (closest to {new_scan_date}): date = {new_scan_real_date}, id = {new_scan_id}")
        
        if old_scan_id == new_scan_id:
            error_message = f"The same scan cannot be used for both comparison points.\nPlease select a different date range if you wish to compare two scans for project '{project_name}'."
            logging.warning(f"create_sast_comparison.SAST_compare_two_scans_by_date: {error_message}")
            raise Exception(error_message)
        
        if old_scan_id is None or new_scan_id is None:
            error_message = f"Failed to find scans for both dates for project '{project_name}'.\nMake sure you have at least two scans to compare in the specified date range."
            logging.warning(f"create_sast_comparison.SAST_compare_two_scans_by_date: {error_message}")
            raise Exception(error_message)
            
        old_scan_results = SAST_api.SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, old_scan_id)
        new_scan_results = SAST_api.SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, new_scan_id)
        
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date: Old scan on {old_scan_real_date} results - {old_scan_results}")
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date: New scan on {new_scan_real_date} results - {new_scan_results}")
        
        fixed_vulnerabilities = SAST_api.SAST_compare_scan_vulnerabilities(old_scan_results, new_scan_results)
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date: Fixed vulnerabilities {fixed_vulnerabilities}")
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date: Scan comparison for project '{project_name}' completed.")
        
        logging.info(f"create_sast_comparison.SAST_compare_two_scans_by_date: Scan comparison for project '{project_name}' completed.")
        return old_scan_results, new_scan_results, fixed_vulnerabilities
    

    except Exception as e:
        print(f"Exception: {e}")
        return None, None, None
    
def SAST_compare_scans_across_all_projects(access_token, SAST_api_url, old_scan_date, new_scan_date):
    
    logging.info("create_sast_comparison.SAST_compare_scans_across_all_projects: Comparing scans across all projects.")
    
    projects = SAST_api.SAST_get_projects(access_token, SAST_api_url)
    all_old_scan_results = {}
    all_new_scan_results = {}
    all_fixed_vulnerabilities = {}
    

    for project in projects:
        project_name = project['name']
        old_scan_results, new_scan_results, fixed_vulnerabilities = SAST_compare_two_scans_by_date(access_token, SAST_api_url, project_name, old_scan_date, new_scan_date)

        all_old_scan_results[project_name] = old_scan_results
        all_new_scan_results[project_name] = new_scan_results
        all_fixed_vulnerabilities[project_name] = fixed_vulnerabilities

    return all_old_scan_results, all_new_scan_results, all_fixed_vulnerabilities
        
def SAST_write_scan_results_to_csv(project_name, old_scan_date, new_scan_date, old_scan_results, new_scan_results, fixed_vulnerabilities, write_headers=False):
    logging.info("create_sast_comparison.SAST_write_scan_results_to_csv: Writing the results of the comparison to a CSV file.")
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
        logging.info("create_sast_comparison.SAST_validate_and_parse_date: Checking if date is in the correct format.")
        if not re.match(r'^\d{1,2}/\d{1,2}/\d{4}$', date_str):
            logging.error("create_sast_comparison.SAST_validate_and_parse_date: Invalid date format. Please use the format 'DD/MM/YYYY'")
            print(f"Invalid date format: {date_str}. Please use the format 'DD/MM/YYYY' or 'D/M/YYYY'.")
            return None

        day, month, year = map(int, date_str.split('/'))
        parsed_date = datetime.datetime(year, month, day)

        current_date = datetime.datetime.now().date()
        if parsed_date.date() > current_date:
            logging.error("create_sast_comparison.SAST_validate_and_parse_date: Date cannot be in the future.")
            print(f"Invalid date: {date_str}. Date cannot be in the future.")
            return None
        
        if year < 1970:
            logging.error(f"create_sast_comparison.SAST_validate_and_parse_date: Year '{year}' is invalid. Earliest supported year is 1970.")
            return None
        
        return parsed_date.date()

    except (ValueError, TypeError):
        print(f"Invalid date: {date_str}. Please provide a valid date in the format 'DD/MM/YYYY'.")
        return None
    
        
    