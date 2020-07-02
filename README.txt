Requirements:
1-Java 11
2-Having Sonarqube installed (https://www.sonarqube.org/downloads)
3-Having SonarScanner installed (https://docs.sonarqube.org/latest/analysis/scan/sonarscanner)
4-Python3

After that, you need to configure the INPUTS of the security_analyzer.py at the begining of the script:

-Path to SonarStart.bat (Downloaded from requirement nº2)
-Path to sonar-scanner.bat (Downloaded from requirement nº3)
-Path to project root directory (The project folder you want to analyze)
-project_name 
-project_key 
-projectVersion 

Finally, run the script with:
>py -3 security_analyzer.py