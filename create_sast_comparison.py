#create_sast_comparison.py

import re
import dateutil.parser
import SAST_api
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
            #print(error_message)
            raise Exception(error_message)
        
        logging.info(f"create_sast_comparison.SAST_compare_two_scans_by_date: Comparing scans for project: '{project_name}', id = {project_id}")

        #print(f"create_sast_comparison.SAST_compare_two_scans_by_date: Comparing scans for project: '{project_name}'")
            
        old_scan_id, old_scan_real_date = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, old_scan_date, search_direction='next')
        new_scan_id, new_scan_real_date = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, new_scan_date, search_direction='last')
        
        logging.info(f"create_sast_comparison.SAST_compare_two_scans_by_date:\nOld scan (closest to {old_scan_date}): date = {old_scan_real_date}, id = {old_scan_id}.\nNew scan (closest to {new_scan_date}): date = {new_scan_real_date}, id = {new_scan_id}")
        
        if old_scan_id is None and new_scan_id is None:
            error_message = f"Failed to find scans for both dates for project '{project_name}'.\nMake sure you have at least one scan in the specified date range."
            logging.warning(f"create_sast_comparison.SAST_compare_two_scans_by_date: {error_message}")
            raise Exception(error_message)
        
        old_scan_results = SAST_api.SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, old_scan_id)
        new_scan_results = SAST_api.SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, new_scan_id)
        
        if old_scan_id == new_scan_id:
            message = f"The same scan is being used for both comparison points for project '{project_name}'.\nThe results will appear at the end of the CSV file."
            logging.info(f"create_sast_comparison.SAST_compare_two_scans_by_date: {message}")
            return old_scan_results, old_scan_real_date, None, None, None
        
        #print(f"create_sast_comparison.SAST_compare_two_scans_by_date: Old scan on {old_scan_real_date} results - {old_scan_results}")
        #print(f"create_sast_comparison.SAST_compare_two_scans_by_date: New scan on {new_scan_real_date} results - {new_scan_results}")
        
        fixed_vulnerabilities = SAST_api.SAST_compare_scan_vulnerabilities(old_scan_results, new_scan_results)
        #print(f"create_sast_comparison.SAST_compare_two_scans_by_date: Fixed vulnerabilities {fixed_vulnerabilities}")
        #print(f"create_sast_comparison.SAST_compare_two_scans_by_date: Scan comparison for project '{project_name}' completed.")
        
        logging.info(f"create_sast_comparison.SAST_compare_two_scans_by_date: Scan comparison for project '{project_name}' completed.")
        return old_scan_results, new_scan_results, fixed_vulnerabilities, old_scan_real_date, new_scan_real_date
    

    except Exception as e:
        #print(f"Exception: {e}")
        return None, None, None, None, None
    
def SAST_compare_scans_across_all_projects(access_token, SAST_api_url, old_scan_date, new_scan_date):
    
    logging.info("create_sast_comparison.SAST_compare_scans_across_all_projects: Comparing scans across all projects.")
    
    projects = SAST_api.SAST_get_projects(access_token, SAST_api_url)
    all_old_scan_results = {}
    all_new_scan_results = {}
    all_fixed_vulnerabilities = {}
    all_old_scan_dates = {}
    all_new_scan_dates = {}
    single_scans_within_date_range_results = {}
    single_scans_within_date_range_real_date = {}

    for project in projects:
        project_name = project['name']
        old_scan_results, new_scan_results, fixed_vulnerabilities, old_scan_real_date, new_scan_real_date = SAST_compare_two_scans_by_date(access_token, SAST_api_url, project_name, old_scan_date, new_scan_date)
        
        if fixed_vulnerabilities is None:
            single_scans_within_date_range_results[project_name] = old_scan_results
            single_scans_within_date_range_real_date[project_name] = new_scan_results
        else:
            all_old_scan_results[project_name] = old_scan_results
            all_new_scan_results[project_name] = new_scan_results
            all_fixed_vulnerabilities[project_name] = fixed_vulnerabilities
            all_old_scan_dates[project_name] = old_scan_real_date
            all_new_scan_dates[project_name] = new_scan_real_date
            

    return all_old_scan_results, all_new_scan_results, all_fixed_vulnerabilities, all_old_scan_dates, all_new_scan_dates, single_scans_within_date_range_results, single_scans_within_date_range_real_date
        
def SAST_write_scan_results_to_csv(project_name, old_scan_date, new_scan_date, old_scan_results, new_scan_results, fixed_vulnerabilities, 
                                   old_scan_real_date, new_scan_real_date, write_headers=False):
    csv_content = io.StringIO()
    writer = csv.writer(csv_content)
    
    if write_headers:
        writer.writerow(['', 'fixed', '', '', old_scan_date, '', '', '', new_scan_date, '', ''])
        writer.writerow(['project', 'high', 'medium', 'low', 'high', 'medium', 'low', 'scan date', 'high', 'medium', 'low', 'scan date'])
    
    writer.writerow([project_name, fixed_vulnerabilities['High'], fixed_vulnerabilities['Medium'], fixed_vulnerabilities['Low'],
                     old_scan_results['High'], old_scan_results['Medium'], old_scan_results['Low'], old_scan_real_date,
                     new_scan_results['High'], new_scan_results['Medium'], new_scan_results['Low'], new_scan_real_date])
    
    return csv_content.getvalue()
    
def SAST_write_scan_results_to_csv_with_one_scan(project_name, scan_date, scan_real_date, scan_results, write_headers=False):
    csv_content = io.StringIO()
    writer = csv.writer(csv_content)
    
    if write_headers:
        writer.writerow(['', 'fixed', '', '', scan_date, '', '', '', '', '', ''])
        writer.writerow(['project', 'high', 'medium', 'low', 'high', 'medium', 'low', 'scan date', 'high', 'medium', 'low', 'scan date'])
    
    if scan_results and scan_real_date:
        writer.writerow([project_name, 0, 0, 0,
                     scan_results['High'], scan_results['Medium'], scan_results['Low'], scan_real_date])
    
    return csv_content.getvalue()

def SAST_validate_and_parse_date(date_str):
    try:
        logging.info("create_sast_comparison.SAST_validate_and_parse_date: Checking if date is in the correct format.")
        if not re.match(r'^\d{1,2}/\d{1,2}/\d{4}$', date_str):
            logging.error("create_sast_comparison.SAST_validate_and_parse_date: Invalid date format. Please use the format 'DD/MM/YYYY'")
            #print(f"Invalid date format: {date_str}. Please use the format 'DD/MM/YYYY' or 'D/M/YYYY'.")
            return None

        day, month, year = map(int, date_str.split('/'))
        parsed_date = datetime.datetime(year, month, day)

        current_date = datetime.datetime.now().date()
        if parsed_date.date() > current_date:
            logging.error("create_sast_comparison.SAST_validate_and_parse_date: Date cannot be in the future.")
            #print(f"Invalid date: {date_str}. Date cannot be in the future.")
            return None
        
        if year < 1970:
            logging.error(f"create_sast_comparison.SAST_validate_and_parse_date: Year '{year}' is invalid. Earliest supported year is 1970.")
            return None
        
        return parsed_date.date()

    except (ValueError, TypeError):
        #print(f"Invalid date: {date_str}. Please provide a valid date in the format 'DD/MM/YYYY'.")
        logging.error(f"Invalid date: {date_str}. Please provide a valid date in the format 'DD/MM/YYYY'.")
        return None