[🔙](https://github.com/JMarkstrom/entra-id-security-key-obo-enrollment/tree/main) 
![](/images/security-key-eobo-with-microsoft-entra-id-integration-overview-diagram.png)

# 💾 Setup intructions
_The following sections cover setup instructions for the script._

### Table of Contents  
[Install Python](#install-python)  
[Install Requests](#install-requests)  
[Install Python-fido2](#install-python-fido2)  
[Install YubiKey Manager CLI](#install-yubikey-managercli)  
[Configure Microsoft Entra ID tenant](#configure-microsoft-entraid-tenant)  
[Download and configure the script files](#download-and-configure-the-script-files)

## Install Python
_The following assumes the target OS is Windows:_

1. Download the Python installer [here](https://www.python.org/downloads/windows/)
2. Once downloaded, locate the file and double-click to run it
3. In the Installer, tick the option to add Python to PATH and select **Install Now**
4. Once finished, verify installation in a command prompt by issuing: ```python --version```

## Install Requests
_To install Requests using pip (bundled with Python) on Windows:_

1. Open PowerShell or Command Prompt
2. Execute command: ```pip install requests```
3. Respond to any prompts to complete installation.

## Install Python-fido2
_To install python-fido2 using pip on Windows:_

1. Open PowerShell or Command Prompt
2. Execute command: ```pip install fido2```
3. Respond to any prompts to complete installation.

## Install YubiKey Manager CLI
_To install YubiKey Manager CLI using pip on Windows:_

1. Open PowerShell or Command Prompt
2. Execute command: ```pip install yubikey-manager```
3. Respond to any prompts to complete installation.

## Configure Microsoft Entra ID tenant

### Create an app registration
_Create an Entra ID app registration for the script to execute under:_

1. Open a browser and navigate to the [**Microsoft Entra admin center**](https://entra.microsoft.com/)
2. Expand Identity (left), **Applications and select App registrations**
3. Click **New registration** (top)
4. Give the application a name and then click **Register**
5. Once created, _copy_ the value of "Application (client) ID" to file for later use
6. Click **Certificates & secrets** (left) and then **New client secret**
7. Provide a description for the secret and then click **Add**
8. Once created, _copy_ the content of (secret) "Value" to file
9. Next, click **API permissions** (left) and then select **Add a permission** (top)
10. Click the Microsoft Graph API tile and then select **Application permissions**
11. Search or expand the permissions list to select: ```UserAuthenticationMethod.ReadWrite.All``` and ```Directory.Read.All```
12. Click **Add permissions**.

### Grant necessary permissions
_Grant admin consent to the application:_

1. Open a browser and navigate to the [**Microsoft Entra admin center**](https://entra.microsoft.com/)
2. Expand **Identity** (left), **Applications** and select **Enterprise applications**
3. Select your newly created application from the list and then select **Permissions**
4. Click **Grant admin consent** and then authenticate as prompted
5. Click **Accept** to confirm permissions assignment to the application.

### Obtain the Entra ID tenant name
_Obtain the tenant name:_

1. Open a browser and navigate to the [**Microsoft Entra admin center**](https://entra.microsoft.com/)
2. Expand **Identity** (left) and select **Overview**
3. Note down the value of "Primary domain".

## Download and configure the script files
_Download script and supporting configuration items:_

1. Download the **sk-entra-id.py** script found [here](https://github.com/JMarkstrom/entra-id-security-key-obo-enrollment/blob/main/script/sk-entra-id.py)
2. Download the **config.json** file found [here](https://github.com/JMarkstrom/entra-id-security-key-obo-enrollment/blob/main/script/config.json)
3. Open 'config.json' in your text editor of choice and populate it
4. Save the file and prepare to run the script.
   

[🔙](https://github.com/JMarkstrom/entra-id-security-key-obo-enrollment/tree/main) 

