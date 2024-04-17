#### Usage: create_sast_comparison.py [optional : <project_name>] <old_scan_date: DD/MM/YYYY> <new_scan_date: DD/MM/YYYY>

- For each project, if no scan was performed on the first (older) date, the next scan after that day will be considered.
- If no scan was performed on the second (newer) date, the last scan previous to that day will be considered.
- The CSV file will still show the dates you picked, even if the actual scan dates are different.
- To check the actual date and id of each scan separately, refer to the console output.
- The script does not take into account failed or cancelled scans.


#### Example Commands
- To compare scans across all projects on specific dates:
  ```
  create_sast_comparison.py 01/01/2023 01/01/2024
  ```
- To compare scans for a specific project:
  ```
  create_sast_comparison.py project_name 01/01/2023 01/01/2024
  ```
