# Checkmarx Scan Comparison Tool

This Python Flask application allows users to compare Checkmarx SAST project scans between two dates. Users can select two dates, an older and a newer date, and the application will retrieve and compare scans for those dates. If a scan was not performed on the specified date, the application will consider the closest scan within that date range. Users can compare scans for a specific project or all projects (leaving the "Project Name" field blank). The results are written to a CSV file, detailing the number of vulnerabilities by severity at each date and the changes in vulnerabilities between the two dates.

### Prerequisites

Before you begin, ensure you have the following:
- Python 3.x installed on your system
- Valid Checkmarx SAST credentials

### Installation

1. Clone the repository or download the source code:

```
git clone https://github.com/idanb10/sast_compare_scans_web.git
cd sast_compare_scans_web
```

2. Set up a virtual environment to manage dependencies (optional but recommended):

```
python -m venv venv
```
- Activating the virtual environment on Windows:

```
venv\Scripts\activate
```

- Activating the virtual environment on macOS and Linux:
```
source venv/bin/activate 
```

3. Install the required Python packages:
```
pip install -r requirements.txt
```

### Configuration

- Rename config_rep_template.yaml to config_rep.yaml.
- Update config_rep.yaml with your Checkmarx SAST credentials and endpoints.

### Running the Application

1. Configure the server's IP address and port by editing `app.py`. You can find the configuration at the bottom of the file:

```
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
```
- You can change `host` and `port` as needed. For example, to allow access from any machine on the network, set host to `0.0.0.0`.

2. Start the server:
```
python app.py
```

3. Access the application via your browser at the configured IP address and port, for example:

```
http://127.0.0.1:5000/
```

- If you changed the host to `0.0.0.0` and are accessing from another machine, replace `127.0.0.1` with the IP address of the machine running the server.

### Usage

1. In the web interface, enter the desired dates in the format `DD/MM/YYYY`. You can also specify a project name (optional). If no project name is provided, scans will be compared from all projects.

2. Click the `Compare Scans` button to initiate the scan comparison.

3. Once the comparison is complete, a CSV file will be generated, showing the vulnerability counts for each project at the older date, newer date, and the number of vulnerabilities fixed between the two dates.

### Logging

The application logs its flow, actual scan dates, warnings, and errors in the app.log file.

