# Project - Penetration Testing

## Objective

1. **Get from the User a Network to Scan**

    1.1 Get from the user a network to scan:
    - The user should have the freedom to choose what network they want to scan.
    - Do not hard code the network into the code.

1.3.2 Full: include Nmap Scripting Engine (NSE), weak passwords, and vulnerability analysis:
    - NSE can be used for vulnerability assessments.
    - Do NOT use the --script vuln NSE category because it is too long and not realistic.
    - Use a script that goes by the name of vuln___ that will give a list of CVEs based on open services.
    - Nmap default scripts are not vulnerability analysis but just enumeration.
    - Note: Full scan also includes a basic scan.

1.4 Make sure the input is valid:
    - The script should have input validation.
    - Ensure that inputs in 1.1 look like IP addresses with their CIDR notation.

2. **Password List for Weak Passwords**

    2.1.1 Have a built-in password list to check for weak passwords:
    - If the user doesn't specify a wordlist to use, a default built-in list should be used automatically.
    - If the user submits their own list, use relative paths instead of absolute paths to reference it.

    2.1.2 Allow the user to supply their own password list:
    - Give the user the choice to choose whether to use their own list.

4. **Result Management**

    4.3 Allow the user to search inside the results:
    - Implement a recurring function to ask for search input and then use grep.
    - Alternatively, implement an external file editor into the script.

    4.4 Allow to save all results into a Zip file:
    - Ask if the user wants to zip all output contents ideally with the directory name provided in 1.2.

## Creativity

- If extra tools are used, ensure to install all required dependencies before the actual code.
- For example, in Python, this will likely be a requirements.txt file.

## How to Run the Script

1. Save the script to a file, for example, `penetration_testing.sh`.
2. Make the script executable:
   ```bash
   chmod +x penetration_testing.sh
   ```
3. Run the script:
   ```bash
   ./penetration_testing.sh
   ```

By following the steps and using the provided script, you will be able to automate the tasks involved in penetration testing efficiently.
