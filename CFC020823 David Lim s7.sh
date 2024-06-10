#!/bin/bash

# Define variables
selected_services=("ssh" "rdp" "ftp" "telnet") #change here to add for services
network=""
output_dir=""
scan_type=""
nmap_command=""
password_list=""

declare -A selected_ports_info

# Check for sudo privileges
check_sudo() {
    if [ "$EUID" -ne 0 ]; then #check for sudo
        echo "Please run this script with sudo."
        exit 1
    fi
}

# Function to iterate over a list of programs and install them
check_programs() {
	check_programs_output=$( {
		echo "Checking and installing necessary programs..."
		echo ""
		declare -A programs=( #list of programme
			["nmap"]="nmap"
			["hydra"]="hydra"
			["masscan"]="masscan"
			["medusa"]="medusa"
			["searchsploit"]="exploitdb"
		)

		for program in "${!programs[@]}"; do #using for loop 
			install "$program" "${programs[$program]}" #jump to the function 
		done

		clone_seclist #run function to check if seclist is installed
		
		echo -e "\nAll checks and installations are complete.\n"		
    } 2>&1 | tee /dev/tty )
}

# Function to check and install a program
install() {
    local program_name=$1
    local package_name=$2

    if ! command -v $program_name &> /dev/null; then #check program using -v
        echo "$program_name is not installed. Installing..."
        sudo apt-get install -y $package_name
    else
        echo "$program_name is already installed."
    fi
}

# Function to clone SecList
clone_seclist() {
    local seclist_dir="/usr/share/seclists" #change here for you own password list
    local seclist_git_repo="https://github.com/danielmiessler/SecLists.git" #seclist respo.

    # Check if the directory exists and is not empty
    if [ -d "$seclist_dir" ] && [ "$(ls -A $seclist_dir)" ]; then #check if seclist is at the location
        echo "SecList is already installed at $seclist_dir."
    else
        echo "SecList is not installed or the directory is empty. Cloning from GitHub into $seclist_dir..."
        sudo git clone $seclist_git_repo $seclist_dir #clone the file
    fi
}

# Get network and output directory name
get_ip() {
	# Prompts user for network and output directory, creates directory
    read -p "Enter the network to scan (IP address or CIDR): " network #ask for input for to scan 
    #network=192.168.115.133 #debug.
    if ! validate "$network"; then #call validate function.
        exit 1
    fi
    #Create dir
    read -p "Enter a name for the output directory: " output_dir #input will create the dir to store the outputs
    #mkdir -p "$output_dir" 
}

# Validate network input
validate() {
    if [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then # validation "xxx.xxx.xxx.xxx/xx"
        return 0
    elif [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then # validation "xxx.xxx.xxx.xxx"
        return 0
    else
        echo "Invalid network format."
        return 1
    fi
}

# Choose scan type
choose_scan_type() {
	# Prompts user to choose between Basic or Full scan
    read -p "Choose scan type: (1) Basic (2) Full: " scan_type #ask for basic or full 1 or 2
    echo ""
    if [[ $scan_type == "1" ]]; then
		echo "Running Nmap scan..."
		nmap_output+="Running Nmap scan..." #to be save in the log
		echo ""
		#nmap_output=$(nmap -sV $network | tee /dev/tty)
		nmap_output=$(nmap -sV -A -p- $network | tee /dev/tty) #to scan all ports
		echo ""
		
		run_masscan	#start the function masscan
		selected_ports "$nmap_output" # stores the list of selected ports
        choose_password_list #this function choose password
        run_password_attacks #run hydra	
        
    elif [[ $scan_type == "2" ]]; then
		echo "Running Nmap scan..."
		echo ""
		#nmap_output=$(nmap -sV $network | tee /dev/tty)
		nmap_output=$(nmap -sV -A -p- $network | tee /dev/tty) #to scan all ports
		echo ""
				
		run_masscan
		selected_ports "$nmap_output" 
        choose_password_list
        run_password_attacks
        run_full_scan_analysis # run nmap --script=vuln -p
        searchspoilt # run searchspoilt
        
    else
        echo "Invalid scan type." # any other input will become this.
        choose_scan_type #dont let it break out.
    fi
}

#run masscan
run_masscan() {
    # Group commands and direct all output to tee
    masscan_output=$(
        {
			echo "Starting masscan to scan udp ports..."
			echo ""
            #masscan -pU:1-1000 --rate 1000 "$network"
            masscan -pU:1-65535 --rate 1000 "$network" #scan all ports 
            echo ""
            echo "Masscan scan completed."
            echo ""
        } 2>&1 | tee /dev/tty  # Redirect both stdout and stderr
    )
}

#store the $service,$port and $version
selected_ports() {
    local nmap_output="$1"

    while read -r line; do
        if [[ $line =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]]+([a-zA-Z0-9_.-]+)[[:space:]]+(.+) ]]; then
            local port=${BASH_REMATCH[1]}
            local service=${BASH_REMATCH[2]}
            local version=${BASH_REMATCH[3]}
            
            # Check if the service is in the selected services list
            if [[ " ${selected_services[*]} " =~ " $service " ]]; then
                selected_ports_info["$service:$port"]="$version"
                #echo "Service: $service, Port: $port, Version: $version" #check if ${selected_services[*] manage to catch the $service,$port and $version
            fi
        fi
    done <<< "$nmap_output"
}

# Choose password list
choose_password_list() {
    #echo -e "\nuser\nmsfadmin\nservice\nroot\npostgres\nftp\nanonymous\npassword" > msfadmin.txt && echo "Password File created at $(pwd)/msfadmin.txt"
	default_location=$(pwd)/msfadmin.txt
    #userlist="$default_location" # use msfadmin.txt
    userlist="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt" #user list from seclist
    #echo "$userlist" #debug
    #cat "$userlist" #check if the username list is working or not
    echo ""
    while true; do
		read -p "Use a custom password list (y/n): " use_custom_list #ask for y/ or *
		case $use_custom_list in
			[yY]|[nN]) break ;;
			*) echo "Invalid input. Please enter y or n." ;;
		esac
	done
    echo ""
    if [[ "$use_custom_list" =~ ^[yY]$ ]]; then #type the path
        read -p "Enter relative path to password list: " password_list #store path into password_list
        echo ""
        if [[ -f "$password_list" ]]; then
            echo "Using custom password list: $password_list"
            echo ""
        else
            echo "Error: Custom password list file not found. Reverting to default password list."
            echo ""
            #password_list="$default_location"
            password_list="/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt" #password list from seclist
            echo "Using default password list at: $password_list"
            echo ""
        fi
    else
		#Default password list from seclist
        #password_list="$default_location"
        password_list="/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt" #password list from seclist
        echo "Using default password list at: $password_list"
        echo ""
        #cat $password_list #for debug to make sure it works.
    fi
}

# Function to run password attacks using Hydra
run_password_attacks() {
    local service_count=0
    echo "Running bruteforce..."
    hydra_output+="Running bruteforce...\n"
    
    # Loop through the selected ports info
    for key in "${!selected_ports_info[@]}"; do
        IFS=':' read -r service port <<< "$key"
        local version=${selected_ports_info[$key]} #get version
        
        local message="Attacking '$service' (Version: $version) on port '$port'\n"
        echo -e "$message" #if never add -e the \n will be printed too.
        hydra_output+="$message\n"
        
        loop_hydra_output=$(hydra -L $userlist -P $password_list -s $port -t 16 $service://$network 2>&1 | tee /dev/tty)
        hydra_output+="$loop_hydra_output\n" # Append each output to the variable
        ((service_count++))
        echo ""
    done
        
    if [[ $service_count -eq 0 ]]; then #if equal to 0 then it will echo nothing
        echo "No known services running for bruteforce."
        hydra_output+="No known services running for bruteforce."    
        echo ""    
    fi
}

# Function to run NSE
run_full_scan_analysis() {
	full_scan_output=$(
		{	
			echo "Running full scan analysis..."
			echo ""
			
			#if no port there is no spoon
			if [ ${#selected_ports_info[@]} -eq 0 ]; then
				echo "No open ports found. Skipping Nmap scans."
				echo ""
                return
            fi
			
			# Iterate over the selected_ports_info array
			for key in "${!selected_ports_info[@]}"; do
				IFS=':' read -r service port <<< "$key"
				local version=${selected_ports_info[$key]}			
				echo "Running Nmap vulnerability scan on $version (port $port)..." # print $version
				echo ""
				local service_output=$(nmap --script=vuln -p "$port" "$network") # run --script=vuln -p 
                echo "$service_output"
                
                #check if the word VULNERABLE is present  
                if echo "$service_output" | grep -q 'VULNERABLE'; then #if got VULNERABLE then
					vulnerability_summary+="ALERT: The $version service on port $port is VULNERABLE. Please update or patch it.\n"					
				fi             
			done
			
			#list of vulnerability		
			if [ -z "$vulnerability_summary" ]; then
                echo "There is no vulnerability found."
                echo ""
            else
                # Print the list of vulnerability
                echo -e "$vulnerability_summary"
                echo ""
            fi			
		} 2>&1 | tee /dev/tty
    )
}

# Function to run searchspoilt -e $version
searchspoilt () {
	searchsploit_output=$(
        {   
            echo "Running searchsploit..."
            echo ""
            
            # Check if there are no entries in selected_ports_info
            if [ ${#selected_ports_info[@]} -eq 0 ]; then
                echo "No open ports found. Skipping searchsploit."
                echo ""
                return
            fi

            # Iterate over the selected_ports_info array
            for key in "${!selected_ports_info[@]}"; do
                IFS=':' read -r service port <<< "$key"
                local version=${selected_ports_info[$key]}

                # Ensure version is not empty and trimmed
                echo "$version"
                
                if [ -n "$version" ]; then
                    echo "Running searchsploit to check vulnerability for $service (version $version) on port $port..."
                    local service_output=$(searchsploit -e $version)
                    echo "$service_output"
                fi
                echo ""
            done
        } 2>&1 | tee /dev/tty
    )
}

# Results menu
results_menu() {
	#add all the output together
	combined_output="${check_programs_output}\n\n${nmap_output}\n\n${masscan_output}\n\n${hydra_output}\n\n${full_scan_output}\n\n${searchsploit_output}"

    while true; do
        echo "Choose an option:"
        echo "1. Search results"
        echo "2. Save results"
        echo "3. Exit"
        echo ""
        read -p "Enter your choice: " option

        #case 1,2,3
        case "$option" in
            1)
                read -p "Enter search term: " search_term #ask for things to grep
                echo "$combined_output" | grep -i "$search_term" ;;
			2)
				read -p "Enter filename for saving results: " save_file #ask for filename
				while true; do
					read -p "Do you want to zip the results? (y/n): " zip_choice
					echo ""
					case "$zip_choice" in
						[Yy]* )
							# Ensure the output directory exists
							mkdir -p "$output_dir"
							# Save and zip the results
							if printf "%b" "$combined_output" > "$output_dir/$save_file.txt" && \
								zip -j "$output_dir/$save_file.zip" "$output_dir/$save_file.txt" > /dev/null; then
								rm "$output_dir/$save_file.txt"
								echo "Results zipped and saved to $output_dir/$save_file.zip"
								echo ""
							else
								echo "Failed to zip the results. Check if the zip utility is installed." #if fail, unlikely
							fi
							break
							;;
						[Nn]* )
							# Ensure the output directory exists & output to $save_file.txt
							mkdir -p "$output_dir"
							printf "%b" "$combined_output" > "$output_dir/$save_file.txt"
							echo "Results saved to $output_dir/$save_file.txt"
							echo ""
							break
							;;
						* )
							echo "Invalid input. Please enter y or n."
							echo ""
							;;
					esac
				done
			;;                                        
            3)
                echo "Exiting..."
                exit 0 ;;
            *)
                echo ""
                echo "Invalid option. Please choose 1, 2, or 3." 
                echo "";;
                
        esac
    done
}

# Main script execution
check_sudo
check_programs
get_ip
choose_scan_type
results_menu
