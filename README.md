# VRV_Security's

Log Analysis Assignment:
This repository contains scripts and resources for analyzing server logs to extract meaningful insights such as request counts, most frequently accessed endpoints, and suspicious activity detection.

Project Structure:
sample.log
    The input file containing server logs for analysis. 
    Each line represents a log entry.

VRV_Security’s_Assignment.py
    The primary Python script for log analysis.
    complete with detailed comments explaining the logic and implementation of each function.

VRV_Security’s_Assignment_without_comments.py
    A streamlined version of the main Python script without any inline comments.
    Suitable for environments where minimal file size or simplicity is desired.

log_analysis_results.csv
    The output file generated by the script, containing the results of the log analysis in CSV format. 
    The file includes:
        1. Requests per IP address
        2. The most frequently accessed endpoint
        3. List of suspicious IPs and their failed login attempts (You can modify the failed login threshold by updating the FAILED_LOGIN_THRESHOLD variable in the script.)
        
How to Run:
1. Ensure Python is Installed.( The scripts require Python 3.x. )
2. Prepare the Log File( Ensure sample.log is in the same directory as the Python scripts. )
3. Run the Script
    Execute the primary script:
    python VRV_Security’s_Assignment.py
    or
    python VRV_Security’s_Assignment_without_comments.py
4. Check the Results
    The analysis results will be saved in log_analysis_results.csv and also displayed in the terminal.

Features:
    1. Request Counting:- Calculates the number of requests made by each IP address.
    2. Endpoint Analysis:- Identifies the most frequently accessed endpoint and its access count.
    3. Suspicious Activity Detection:- Detects IPs with excessive failed login attempts (threshold set at 10 by default).
