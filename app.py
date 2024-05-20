#app.py

from flask import Flask, jsonify, make_response, render_template, request
from markupsafe import escape
from dateutil.relativedelta import relativedelta
import datetime
import yaml
import create_sast_comparison
import SAST_api
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='app.log', filemode='a')

with open('config_rep.yaml', 'r') as file:
    config = yaml.safe_load(file)

SAST_username = config['SAST_username']
SAST_password = config['SAST_password']
SAST_server_name = config['SAST_server_name']
report_server_name = config['report_server_name']
port = config['port']
debug = config['debug']
SAST_auth_url = f"{SAST_server_name}/CxRestAPI/auth/identity/connect/token"
SAST_api_url = f"{SAST_server_name}/CxRestAPI"

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    print(f"{datetime.datetime.now()} - Program starting... check the app.log file for the application's flow, actual scan dates, warnings, and errors.")
    logging.info("app.index: Handling GET / request.")
    
    current_date = datetime.datetime.now()
    one_month_ago = current_date - relativedelta(months=1)
    
    current_date_str = current_date.strftime("%d/%m/%Y")
    one_month_ago_str = one_month_ago.strftime("%d/%m/%Y")

    return render_template('index.html', default_new_date=current_date_str, default_old_date=one_month_ago_str)

@app.route('/compare', methods=['POST'])
def compare_scans():
    logging.info("\n" + "-" * 50)
    logging.info("Starting a new comparison.")
    logging.info(f"app.compare_scans: Handling POST /compare request.")
    
    access_token = SAST_api.SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url)
    if not access_token:
        error_message = "Failed to obtain access token."
        logging.error("app.compare_scans: Failed to obtain access token. Please check the 'config_rep.yaml' for correct SAST credentials.")
        #print(error_message)
        return jsonify({"error": error_message})
    
    project_name = escape(request.form['project_name'])
    old_scan_date_str = escape(request.form['old_scan_date'])
    new_scan_date_str = escape(request.form['new_scan_date'])
    
    logging.info(f"app.compare_scans: Validating user input...")
    
    old_scan_date = create_sast_comparison.SAST_validate_and_parse_date(old_scan_date_str)
    new_scan_date = create_sast_comparison.SAST_validate_and_parse_date(new_scan_date_str)
    

    if old_scan_date is None or new_scan_date is None:
        error_message = "One or more dates are invalid. Please use the format 'DD/MM/YYYY'."
        logging.error(f"app.compare_scans: {error_message}")
        #print(error_message)
        return jsonify({"error": error_message})

    if old_scan_date > new_scan_date:
        error_message = "The old scan date should be earlier than the new scan date."
        logging.error(f"app.compare_scans: {error_message}")
        #print(error_message)
        return jsonify({"error": error_message})       
    
    logging.info("app.compare_scans: Checking if project name was provided.")
 
    if project_name:
        logging.info(f"app.compare_scans: Checking if project '{project_name}' exists under your credentials.")
        project_found = False
        projects = SAST_api.SAST_get_projects(access_token=access_token, SAST_api_url=SAST_api_url)
        for project in projects:
            if project['name'] == project_name:
                project_found = True
                break
        if project_found == False:
            error_message = f"No project named '{project_name}' was found."
            logging.error(f"app.compare_scans: {error_message}")
            #print(error_message)
            return jsonify({"error": error_message})
    
    old_scan_date_str = old_scan_date.strftime('%Y-%m-%d')
    new_scan_date_str = new_scan_date.strftime('%Y-%m-%d')
    
    csv_filename = ""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        if project_name:
            logging.info(f"app.compare_scans: Project name was provided. Preparing to compare scans for project '{project_name}'.")
            
            old_scan_results, new_scan_results, fixed_vulnerabilities, old_scan_real_date, new_scan_real_date = create_sast_comparison.SAST_compare_two_scans_by_date(access_token, SAST_api_url, \
                project_name, old_scan_date_str, new_scan_date_str)
            if old_scan_results is None or new_scan_results is None or fixed_vulnerabilities is None:
                logging.error("app.compare_scans: Failed to compare scans for the specified project.")
                raise Exception("Failed to compare scans for the specified project.")
            csv_content = create_sast_comparison.SAST_write_scan_results_to_csv(project_name, old_scan_date_str, new_scan_date_str, old_scan_results,
                new_scan_results, fixed_vulnerabilities, old_scan_real_date, new_scan_real_date, write_headers=True)
            csv_filename = f'SAST_Comparison_for_Project_{project_name}_{old_scan_date_str}_to_{new_scan_date_str}__{timestamp}.csv'
        else:
            logging.info("app.compare_scans: Project name was not provided. Preparing to compare scans for all projects.")
            
            all_old_scan_results, all_new_scan_results, all_fixed_vulnerabilities, all_old_scan_real_dates, all_new_scan_real_dates = create_sast_comparison.SAST_compare_scans_across_all_projects(access_token,
                SAST_api_url, old_scan_date_str, new_scan_date_str)
            
            if not all_old_scan_results or not all_new_scan_results or not all_fixed_vulnerabilities:
                logging.error("Failed to compare scans across all projects.")
                raise Exception("Failed to compare scans across all projects.")
            
            csv_content = ""
            write_headers = True
            for project_name in all_old_scan_results:
                old_scan_results = all_old_scan_results[project_name]
                new_scan_results = all_new_scan_results[project_name]
                fixed_vulnerabilities = all_fixed_vulnerabilities[project_name]
                old_scan_real_date = all_old_scan_real_dates[project_name]
                new_scan_real_date = all_new_scan_real_dates[project_name]
                
                if old_scan_results is not None and new_scan_results is not None and fixed_vulnerabilities is not None:
                    csv_content += create_sast_comparison.SAST_write_scan_results_to_csv(project_name, old_scan_date_str, new_scan_date_str, old_scan_results,
                                                                                    new_scan_results, fixed_vulnerabilities, old_scan_real_date, 
                                                                                    new_scan_real_date, write_headers=write_headers)
                    write_headers = False
                    if not csv_content.endswith("\n"):
                        csv_content += "\n"

            csv_filename = f'SAST_Comparison_{old_scan_date_str}_to_{new_scan_date_str}__{timestamp}.csv'
        
        if not csv_content:
            error_message = "No scans to compare within the specified date range."
            logging.warning(f"app.compare_scans: {error_message}")
            return jsonify({"error": error_message}) 
                
        logging.info("app.compare_scans: CSV file written successfully.")
        #print("app.compare_scans: CSV file written successfully.")
        
        response = make_response((csv_content, 200, {'Content-Disposition': f'attachment; filename={csv_filename}', 'Content-Type': 'text/csv'}))
        return response

    except Exception as e:
        error_message = str(e)
        return render_template('index.html', error=error_message)

if __name__ == '__main__':
    app.run(host=report_server_name, port=port, debug=debug)