from flask import Flask, jsonify, make_response, render_template, request, send_from_directory
import yaml
import create_sast_comparison
import SAST_api
import os
import datetime


with open('config_rep.yaml', 'r') as file:
    config = yaml.safe_load(file)

SAST_username = config['SAST_username']
SAST_password = config['SAST_password']
SAST_auth_url = config['SAST_auth_url']
SAST_api_url = config['SAST_api_url']

app = Flask(__name__)


@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/compare', methods=['POST'])
def compare_scans():
    project_name = request.form['project_name']
    old_scan_date_str = request.form['old_scan_date']
    new_scan_date_str = request.form['new_scan_date']

    old_scan_date = create_sast_comparison.SAST_validate_and_parse_date(old_scan_date_str)
    new_scan_date = create_sast_comparison.SAST_validate_and_parse_date(new_scan_date_str)
    
    access_token = SAST_api.SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url)
    if not access_token:
        error_message = "Failed to obtain access token."
        return jsonify({"error": error_message})
    
    if old_scan_date is None or new_scan_date is None:
        error_message = "One or more dates are invalid. Please enter dates in the format DD/MM/YYYY."
        return jsonify({"error": error_message})

    if old_scan_date > new_scan_date:
        error_message = "The old scan date should be earlier than the new scan date."
        return jsonify({"error": error_message})

        
    if project_name:
        project_found = False
        projects = SAST_api.SAST_get_projects(access_token=access_token, SAST_api_url=SAST_api_url)
        for project in projects:
            if project['name'] == project_name:
                project_found = True
                break
        if project_found == False:
            error_message = f"No project named {project_name} was found."
            return jsonify({"error": error_message})

    
    old_scan_date_str = old_scan_date.strftime('%Y-%m-%d')
    new_scan_date_str = new_scan_date.strftime('%Y-%m-%d')
    
    csv_filename = ""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    #FOR TESTS, REMOVE LATER
    #create_sast_comparison.SAST_compare_all_latest_vulnerabilities(SAST_username, SAST_password, SAST_auth_url, SAST_api_url)
    
    try:
        if project_name:
            old_scan_results, new_scan_results, fixed_vulnerabilities = create_sast_comparison.SAST_compare_two_scans_by_date(SAST_username, SAST_password, \
                SAST_auth_url, SAST_api_url, project_name, old_scan_date_str, new_scan_date_str)
            if old_scan_results is None or new_scan_results is None or fixed_vulnerabilities is None:
                raise Exception("Failed to compare scans for the specified project.")
            csv_content = create_sast_comparison.SAST_write_scan_results_to_csv(project_name, old_scan_date_str, new_scan_date_str, old_scan_results,\
                new_scan_results, fixed_vulnerabilities, write_headers=True)
            csv_filename = f'SAST_Comparison_for_Project_{project_name}_{old_scan_date_str}_to_{new_scan_date_str}__{timestamp}.csv'
        else:
            all_old_scan_results, all_new_scan_results, all_fixed_vulnerabilities = create_sast_comparison.SAST_compare_scans_across_all_projects(SAST_username, \
                SAST_password, SAST_auth_url, SAST_api_url, old_scan_date_str, new_scan_date_str)
            if not all_old_scan_results or not all_new_scan_results or not all_fixed_vulnerabilities:
                raise Exception("Failed to compare scans across all projects.")
            
            csv_content = ""
            write_headers = True
            for project_name in all_old_scan_results:
                old_scan_results = all_old_scan_results[project_name]
                new_scan_results = all_new_scan_results[project_name]
                fixed_vulnerabilities = all_fixed_vulnerabilities[project_name]
                if old_scan_results is not None and new_scan_results is not None and fixed_vulnerabilities is not None:
                    csv_content += create_sast_comparison.SAST_write_scan_results_to_csv(project_name, old_scan_date_str, new_scan_date_str, old_scan_results, \
                                                                                    new_scan_results, fixed_vulnerabilities, write_headers=write_headers)
                    write_headers = False
                    if not csv_content.endswith("\n"):
                        csv_content += "\n"
            csv_filename = f'SAST_Comparison_{old_scan_date_str}_to_{new_scan_date_str}__{timestamp}.csv'
        
        # response = make_response(csv_content)
        # response.headers['Content-Disposition'] = f'attachment; filename={csv_filename}'
        # response.headers['Content-Type'] = 'text/csv'
        # response.set_cookie('end_of_comparison', 'true')
        # return response
        response = make_response((csv_content, 200, {'Content-Disposition': f'attachment; filename={csv_filename}', 'Content-Type': 'text/csv'}))
        return response

    except Exception as e:
        error_message = str(e)
        return render_template('index.html', error=error_message)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)