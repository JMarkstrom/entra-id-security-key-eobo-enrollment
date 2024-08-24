######################################################################
# Security Key Enrollment-On-Behalf-Of (EOBO) for Microsoft Entra ID                   
######################################################################
# version: 1.3
# last updated on: 2024-08-17 by Jonas Markström (swjm.blog)
# see readme.md for more info.
#
# DEPENDENCIES: 
#   - Microsoft Entra ID app registration must be configured
#   - YubiKey Manager (ykman) must be installed on the system
#   - Python-fido2 must be installed on the system 
#   - Requests must be installed on the system
#
# LIMITATIONS/ KNOWN ISSUES: N/A
# 
# USAGE: python sk-entra-id.py
#
# BSD 2-Clause License                                                             
# Copyright (c) 2024, Jonas Markström 
# Copyright (c) 2024, Yubico AB
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
######################################################################

# Standard Library Imports
import base64
import datetime
import json
import os
import re
import secrets
import sys
import time
from threading import Timer
import platform
from time import sleep

# Third-Party Library Imports
import click
import requests
from contextlib import contextmanager
from fido2.client import Fido2Client, UserInteraction
from fido2.ctap2 import Ctap2, ClientPin, Config
from fido2.ctap2.extensions import CredProtectExtension
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_encode
import string

# Local Imports
from ykman import scripting as s
from yubikit.management import (
    ManagementSession,
    DeviceConfig,
)
from ykman.device import list_ctap_devices
from yubikit.core.fido import FidoConnection


# Function to display program banner
def banner():
    """
    Displays an ASCII art banner to the console.
    """
    click.clear()
    click.secho("                                                                                            ")
    click.secho("Welcome to:                                                                                 ")
    click.secho("▒░░░░░░░░░░░░░░░░░░░░  ▒░░░░░░░░░░░░░░░░░░░░  ▒░░░░░░░░░░░░░░░░░░░░  ▒░░░░░░░░░░░░░░░░░░░░  ")
    click.secho("▒░░░░░░░▒▒▒▒░░░░░░░░▒  ▒░░░░░░░▒▒▒▒░░░░░░░░▒  ▒░░░░░░░▒▒▒▒░░░░░░░░▒  ▒░░░░░░░▒▒▒▒░░░░░░░░▒  ")
    click.secho("▒░░░░░░░▒  ▒░░░░░░░░▒  ▒░░░░░░░▒  ▒░░░░░░░░▒  ▒░░░░░░░▒  ▒░░░░░░░░▒  ▒░░░░░░░▒  ▒░░░░░░░░▒  ")
    click.secho("▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ")
    click.secho("▒░░░░░░░░░░░░░▒░█▀▀░█▀▀░█▀▀░█░█░█▀▄░▀█▀░▀█▀░█░█░░░█░█░█▀▀░█░█░░░█▀▀░█▀█░█▀▄░█▀█░v.1.3░░░░▒  ")
    click.secho("▒░░░░░░░░░░░░░▒░▀▀█░█▀▀░█░░░█░█░█▀▄░░█░░░█░░░█░░░░█▀▄░█▀▀░░█░░░░█▀▀░█░█░█▀▄░█░█░░░░░░░░░░▒  ")
    click.secho("▒░░░░░░░▒▒▒▒▒░░░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░░░▀░░░░▀░▀░▀▀▀░░▀░░░░▀▀▀░▀▀▀░▀▀░░▀▀▀░░░░░░░░░░▒  ")
    click.secho("▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ")
    click.secho("▒░░░░░▒███▓███▒░░░░░▒  ▒░░░░░▒███▓███▒░░░░░▒  ▒░░░░░▒███▓███▒░░░░░▒  ▒░░░░░▒███▓███▒░░░░░▒  ")
    click.secho("▒░░░░▒███▒▓▒███░░░░░▒  ▒░░░░▒███▒▓▒███░░░░░▒  ▒░░░░▒███▒▓▒███░░░░░▒  ▒░░░░▒███▒▓▒███░░░░░▒  ")
    click.secho("▒░░░░▒███▓▒████▒░░░░▒  ▒░░░░▒███▓▒████▒░░░░▒  ▒░░░░▒███▓▒████▒░░░░▒  ▒░░░░▒███▓▒████▒░░░░▒  ")
    click.secho("▒░░░░░▓██▓████▓░░░░░▒  ▒░░░░░▓██▓████▓░░░░░▒  ▒░░░░░▓██▓████▓░░░░░▒  ▒░░░░░▓██▓████▓░░░░░▒  ")
    click.secho("▒░░░░░░▒▓███▓▒░░░░░░▒  ▒░░░░░░▒▓███▓▒░░░░░░▒  ▒░░░░░░▒▓███▓▒░░░░░░▒  ▒░░░░░░▒▓███▓▒░░░░░░▒  ")
    click.secho("▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ")
    click.secho("▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ▒░░░░░░░░░░░░░░░░░░░▒  ")
    click.secho("░▒▒░░░░░░░░░░░░░░░░▒░  ░▒▒░░░░░░░░░░░░░░░░▒░  ░▒▒░░░░░░░░░░░░░░░░▒░  ░▒▒░░░░░░░░░░░░░░░░▒░  ")
    click.secho("    ░░░░░░░░░░░░░          ░░░░░░░░░░░░░          ░░░░░░░░░░░░░          ░░░░░░░░░░░░░      ")
    click.secho("    ░░▓▓▓▓▓▓▓▓▓░░          ░░▓▓▓▓▓▓▓▓▓▒░          ░░▓▓▓▓▓▓▓▓▓▒░          ░░▓▓▓▓▓▓▓▓▓▒░      ")
    click.secho("    ░▒▓█▓█▓█▓█▓░░          ░░▓█▓█▓█▓█▓▒░          ░▒▓█▓█▓█▓█▓░░          ░▒▓█▓█▓█▓█▓░░      ")
    click.secho("    ░▒▓█▓█▓█▓█▓░░          ░░▓█▓█▓█▓█▓▒░          ░▒▓█▓█▓█▓█▓░░          ░▒▓█▓█▓█▓█▓░░      ")
    click.secho("    ░░▓█▓█▓█▓█▓░░          ░░▓█▓█▓█▓█▓░░          ░░▓█▓█▓█▓█▓░░          ░░▓█▓█▓█▓█▓░░      ")
    click.secho("                                                                                            ")


# Function to obtain OAuth access token from Microsoft Graph API
def send_token_request(token_endpoint, headers, body):
    """
    Sends a token request to the specified token endpoint.

    Args:
        token_endpoint (str): The token endpoint URL.
        headers (dict): The HTTP headers for the request.
        body (dict): The request body.

    Returns:
        requests.Response: The response object.
    """
    response = requests.post(token_endpoint, data=body, headers=headers, verify=False)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response


# Function setting the HTTP headers for Microsoft Graph API
def set_http_headers(access_token):
    """
    Sets the HTTP headers required for making requests to the Microsoft Graph API.

    This function takes an access token as input and returns a dictionary containing
    the necessary headers for authenticating and formatting the requests to the Microsoft Graph API.

    Args:
        access_token (str): The access token obtained from the authentication process.

    Returns:
        dict: A dictionary containing the HTTP headers for the Microsoft Graph API requests.
    """
    return {
        "Accept": "application/json",
        "Authorization": access_token,
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
    }


# Function to construct request body when accessing Microsoft Graph API
def construct_request_body(client_id, client_secret):
    """
    Constructs the request body for obtaining an access token.

    Args:
        client_id (str): The client ID of the application.
        client_secret (str): The client secret of the application.

    Returns:
        dict: The constructed request body.
    """
    return {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }


# Function to parse access token in response from Microsoft Graph API
def extract_access_token(response):
    """
    Extracts the access token from the response.

    Args:
        response (requests.Response): The response object.

    Returns:
        str: The extracted access token.
    """
    access_token = re.search('"access_token":"([^"]+)"', str(response.content))
    if not access_token:
        raise ValueError("Access token not found in response")
    return access_token.group(1)


# Function to retrieve acces token from Microsoft Graph API
def get_access_token_for_microsoft_graph(client_id, client_secret, tenant_id):
    """
    Retrieves an access token for accessing Microsoft Graph API using OAuth client credentials flow.

    Args:
        client_id (str): The client ID of the application.
        client_secret (str): The client secret of the application.
        tenant_id (str): The name of the Entra directory as an fqdn.

    Returns:
        str: The access token.
    """
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_endpoint = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    body = construct_request_body(client_id, client_secret)

    token_response = send_token_request(token_endpoint, headers, body)

    access_token = extract_access_token(token_response)

    return access_token


# Set variable to control PIN length
pin_length = 4

# Check if program is running as administrator
"""
Checks if the script is running with administrative privileges (required on Windows).
"""
if platform.system() == "Windows":
    import ctypes

    if ctypes.windll.shell32.IsUserAnAdmin() != 0:
        pass
    else:
        click.clear()
        banner()
        click.pause(
            "🛑 Program is not running as administrator (press any key to exit)"
        )
        click.clear()
        # Exit program in 3 seconds
        for i in range(3, 0, -1):  # Countdown from 3 seconds
            click.secho(f"Exiting program in {i} seconds...")
            time.sleep(1)
            click.clear()
        click.clear()
        sys.exit(1)
else:
    pass


# Check for config file
"""
This is the JSON file containing details of the Microsoft Entra ID app registration
necessary to connect and provision our user(s). See readme.md for more information!
"""
script_dir = os.path.dirname(os.path.abspath(__file__))
config_file = os.path.join(script_dir, "config.json")

if not os.path.exists(config_file):
    banner()
    click.pause("🛑 Config file not found (press any key to continue)")
    click.clear()
    # Prompt for config file path if not found
    banner()
    config_file = click.prompt("Please provide a path to the config file", type=str)

try:
    with open(config_file, "r", encoding="utf8") as f:
        config = json.load(f)
except FileNotFoundError:
    banner()
    click.pause(f"🛑 Config file not found (press any key to exit)")
    click.clear()
    # Exit program in 3 seconds
    for i in range(3, 0, -1):  # Countdown from 3 seconds
        click.secho(f"Exiting program in {i} seconds...")
        time.sleep(1)
        click.clear()
    click.clear()
    sys.exit(1)
except json.JSONDecodeError:
    banner()
    click.pause("🛑 Error decoding JSON (press any key to exit)")
    click.clear()
    # Exit program in 3 seconds
    for i in range(3, 0, -1):  # Countdown from 3 seconds
        click.secho(f"Exiting program in {i} seconds...")
        time.sleep(1)
        click.clear()
    click.clear()
    sys.exit(1)
else:
    pass


# Config attributes we need
client_id = config["client_id"]
client_secret = config["client_secret"]
tenant_id = config["tenant_id"]


# Check for output file
"""
Programmed YubiKeys will be written to an output file.
"""
# Initialize output data as an empty list
data = []
# Create the output file
with open("output.json", "w") as jsonfile:
    json.dump(data, jsonfile)


# Disable warnings(!)
# See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
requests.packages.urllib3.disable_warnings()


# Connect to Microsoft Graph API and get access token
access_token = get_access_token_for_microsoft_graph(client_id, client_secret, tenant_id)


# Function that runs the entire YubiKey programming and registration sequence
def yubikey_eob_registration(config):

    # Function to write configuration of YubiKey to file
    def write_json():
        """
        Writes programmed YubiKey information to a JSON file.
        The modified data is written to the 'output.json' file.
        """
        new_data = []
        # Add programmed YubiKey information to JSON data
        new_data.append(
            {
                "Name": user_display_name,
                "UPN": user_name,
                "Model": device.name,
                "Serial number": serial_number,
                "PIN": pin,
                "PIN change required": pin_change,
                "Secure Transport Mode": nfc_restricted
            }
        )
        data.append(new_data)

        # Write the modified data back to the JSON file
        with open("output.json", "w") as jsonfile:
            json.dump(data, jsonfile, indent=4)

    
    # Function to prompt user for touching the YubiKey
    def prompt_for_touch():
        """
        Prompts the user to touch the inserted YubiKey.

        Clears the screen and displays a message instructing the user to touch the YubiKey.

        Raises:
            OSError: If clearing the screen fails.

        Example:
            prompt_for_touch() OR prompt_timeout()
        """
        try:
            banner()
            click.echo("Touch YubiKey...", err=True)
        except Exception:
            sys.stderr.write("Touch YubiKey...")

    
    # Function for touch timeout during prompt
    @contextmanager
    def prompt_timeout(timeout=0.5):
        """
        Context manager providing a timeout for a prompt (touch) operation.

        Sets a timeout for a prompt operation. If the operation exceeds the specified
        timeout, it is automatically canceled. Timeout duration is in seconds.

        Args:
            timeout (float, optional): Duration of the timeout in seconds. Default is 0.5 seconds.

        Example: prompt_timeout()

        """
        timer = Timer(timeout, prompt_for_touch)
        try:
            timer.start()
            yield None
        finally:
            timer.cancel()

    
    # Function to handle removal and reinsertion of YubiKey
    def prompt_re_insert():
        """
        Continuously checks for the re-insertion of a YubiKey after it has been removed.

        This function monitors the connected FIDO devices by calling the list_ctap_devices()
        function periodically. If a device is removed, it waits for it to be re-inserted.

        Returns:
            Union[FidoConnection, None]: An instance of FidoConnection representing the
            re-inserted FIDO device if found, or None if no device is re-inserted.
        """

        removed = False
        while True:
            sleep(0.5)
            keys = list_ctap_devices()
            if not keys:
                removed = True
            if removed and len(keys) == 1:
                return keys[0].open_connection(FidoConnection)

    
    # Function to reset the FIDO application of a YubiKey
    def reset_yubikey():
        """
        Resets the FIDO application (U2F and FIDO2) of a YubiKey.

        This function guides the user through the process of resetting the FIDO application on a YubiKey.
        It displays a warning and then performs the reset if the YubiKey matches the expected serial number.

        Args:
            None
        Raises:
            SystemExit: If no YubiKey is re-inserted, the function exits with a status code of 1.
        """
        banner()
        # Warn user of FIDO2 application reset
        if click.confirm(
            "YubiKey will be reset. Do you want to continue?", default=True
        ):
            click.clear()
        else:
            # Exit program in 3 seconds
            for i in range(3, 0, -1):  # Countdown from 3 seconds
                banner()
                click.secho(f"Exiting program in {i} seconds...")
                time.sleep(1)
                click.clear()
                click.clear()
            sys.exit(1)

        # Now reset the YubiKey FIDO application
        banner()
        click.echo("Remove and re-insert YubiKey...")

        connection = prompt_re_insert()

        # Read serial number of (re)inserted YubiKey to perform comparison
        reinserted_device = ManagementSession(connection).read_device_info().serial

        if reinserted_device:
            if reinserted_device == serial_number:
                with prompt_timeout():
                    Ctap2(connection).reset()
                banner()
                click.secho("Reset successful.")
                time.sleep(1)
            else:
                
                # Check if the (re)inserted YubiKey has a different serial number than expected
                if reinserted_device != serial_number:
                    banner()
                    click.pause(f"🛑 Expected Serial Number '{serial_number}', but found '{reinserted_device}' (press any key to continue...)")
                    # Call reset_yubikey again to restart the process if the serial number is incorrect
                    reset_yubikey()
        else:
            banner()
            #click.echo("No YubiKey re-inserted. Exiting...")
            click.pause(f"🛑 Expected Serial Number '{serial_number}', but no Serial Number was detected (press any key to continue...)")
            # Call reset_yubikey again to restart the process if the serial number is incorrect
            reset_yubikey()

        click.clear()

    
    # Function to hold dictionary of banned FIDO2 PIN codes
    """
    This list contains disallowed PINs as per Yubico's 2024 PIN complexity rules. For more information: 
    https://docs.yubico.com/hardware/yubikey/yk-tech-manual/5.7-firmware-specifics.html#pin-complexity
    
    NOTE: This script currently does not enforce PIN complexity or PIN length. Instead it makes sure the 
    random PIN generated complies with these settings, if set prior. Note also that if PIN length is '4'
    then the check against the list of disallowed PINs is "less" relevant. Lastly, since we are generating
    numerical PINs it is not necessary to disallow alphanumerical PINs.
    """
    disallowed_pins = [
        "123456",
        "123123",
        "654321",
        "123321",
        "112233",
        "121212",
        "520520",
        "123654",
        "159753",
        
    ] # Add more as you see fit!

    
    # Function to generate random FIDO2 PIN codes
    def generate_random_pin():
        """
        Generates a random numerical PIN.

        This function utilizes the secrets module to securely generate a random PIN.
        The PIN consists of numerical digits (0-9) and does not contain any letters or special characters.
        Trivial PINs (e.g., all digits are the same) and PINs in the banned list are disallowed.

        Returns:
            str: A string representing the generated PIN.
        """
        while True:
            digits = "".join(
                secrets.choice(string.digits) for _ in range(pin_length)
            )  # PIN will be 4 digits (change to 6 if needed)
            # Check if PIN is not trivial and not in banned list
            if len(set(digits)) != 1 and digits not in disallowed_pins:
                return digits

    
    # Function to set PIN on the YubiKey
    def set_fido_pin(pin):
        """
        Set the FIDO2 PIN on the inserted YubiKey.

        If a PIN is already set, the function will first reset the FIDO2 applet before setting a new PIN.
        If no PIN is set, it will directly set a new PIN.

        Args:
            pin (str): The desired PIN to be set on the YubiKey.

        Raises:
            Exception: If there is an error while setting the PIN or resetting the FIDO2 applet.
        """

        devices = list(CtapHidDevice.list_devices())
        ctap = Ctap2(devices[0])

        # Determine PIN status of inserted YubiKey
        if ctap.info.options.get("clientPin"):

            # Call reset of the FIDO2 applet if PIN is already set
            reset_yubikey()
            # Reconnect to YubiKey
            devices = list(CtapHidDevice.list_devices())
            ctap = Ctap2(devices[0])
            # Set a random PIN
            client_pin = ClientPin(ctap)
            client_pin.set_pin(pin)

        else:
            # Reconnect to YubiKey
            devices = list(CtapHidDevice.list_devices())
            ctap = Ctap2(devices[0])
            # Set a random PIN
            client_pin = ClientPin(ctap)
            client_pin.set_pin(pin)

    
    # Function to get FIDO credentials authentication options
    def get_fido2_creation_options(userID, access_token):
        """
        Retrieve FIDO2 credential creation options for a user from the Microsoft Graph API.

        Sends a GET request to the FIDO2 credential creation options endpoint, passing the user ID and an access token for authentication.
        The challenge timeout value is retrieved from a configuration file and included as a query parameter.

        Args:
            userID (str): The ID of the user for whom to retrieve the FIDO2 credential creation options.
            access_token (str): A valid access token for authentication with the Microsoft Graph API.

        Returns:
            tuple: A tuple containing a boolean indicating success or failure and either the FIDO2 credential creation options or None.
        """
        headers = set_http_headers(access_token)
        params = {"challenge_timeout": 5}  # Five minute timeout

        # TODO: update from beta to v1.0 endpoint when GA.

        fido_credentials_endpoint = (
            "https://graph.microsoft.com/beta/users/"
            + userID
            + "/authentication/fido2Methods/creationOptions"
        )

        response = requests.get(
            fido_credentials_endpoint, headers=headers, params=params, verify=False
        )
        if response.status_code == 200:
            creation_options = response.json()

            return True, creation_options
        else:
            return False, None

    
    # Function to convert from Base64
    def base64url_to_bytearray(b64url_string):
        """
        Convert a Base64 URL-safe string to a bytearray.

        Args:
            b64url_string (str): The Base64 URL-safe string to be converted.

        Returns:
            bytearray: The decoded bytes from the input string.
        """
        temp = b64url_string.replace("_", "/").replace("-", "+")
        return bytearray(base64.urlsafe_b64decode(temp + "=" * (4 - len(temp) % 4)))

    
    # Define function
    def build_creation_options(challenge, userId, displayName, name):
        """
        Build the PublicKeyCredentialCreationOptions object for WebAuthn registration.

        Args:
            challenge (str): A base64url-encoded challenge string.
            userId (str): A base64url-encoded user ID string.
            displayName (str): The user's display name.
            name (str): The user's name.

        Returns:
            dict: The PublicKeyCredentialCreationOptions object for WebAuthn registration.
        """
        public_key_credential_creation_options = {
            "publicKey": {
                "challenge": base64url_to_bytearray(challenge),
                "timeout": 0,
                "attestation": "direct",
                "rp": {"id": "login.microsoft.com", "name": "Microsoft"},
                "user": {
                    "id": base64url_to_bytearray(userId),
                    "displayName": displayName,
                    "name": name,
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},
                    {"type": "public-key", "alg": -257},
                ],
                "excludeCredentials": [],
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "requireResidentKey": True,
                    "userVerification": "required",
                },
                "extensions": {
                    "hmacCreateSecret": True,
                    "enforceCredentialProtectionPolicy": True,
                    "credentialProtectionPolicy": CredProtectExtension.POLICY.OPTIONAL,
                },
            }
        }

        return public_key_credential_creation_options

    # Handle user interaction during credential creation
    class CliInteraction(UserInteraction):
        """
        Handle user interaction during WebAuthn credential creation.

        Implements the `UserInteraction` interface and provides methods for:
        - Prompting the user to touch their authenticator (e.g., YubiKey)
        - Requesting a PIN
        - Requesting user verification (UV) when necessary during the WebAuthn registration process
        """

        def prompt_up(self):
            banner()
            click.secho("Touch YubiKey...")

        def request_pin(self, permissions, rp_id):
            return pin

        def request_uv(self, permissions, rp_id):
            banner()
            print("User Verification required.")
            return True

    
    # Function to create and activate YubiKey in Microsoft Entra ID
    def create_and_activate_fido_method(
        credential_id,
        client_extensions,
        user_name,
        attestation,
        client_data,
        serial_number,
        access_token,
    ):
        """
        Create and activate a FIDO2 authentication method for a user in Microsoft Entra ID.

        Sends a POST request to the FIDO2 authentication method creation endpoint with the provided parameters,
        including the credential ID, attestation object, client data, and client extension results.

        Args:
            credential_id (str): The credential ID of the FIDO2 authentication method.
            client_extensions (str): The client extension results encoded as a base64 string.
            user_name (str): The user's name.
            attestation (str): The attestation object.
            client_data (str): The client data.
            serial_number (str): The serial number of the security key.
            access_token (str): The access token for authentication.

        Returns:
            tuple: A tuple containing a boolean indicating success or failure and either the created method ID or an empty list.
        """
        headers = set_http_headers(access_token)

        fido_credentials_endpoint = (
            "https://graph.microsoft.com/v1.0/users/"
            + user_name
            + "/authentication/fido2Methods"
        )

        body = {
            "publicKeyCredential": {
                "id": credential_id,
                "response": {
                    "attestationObject": attestation,
                    "clientDataJSON": client_data,
                },
                "clientExtensionResults": json.loads(
                    base64.b64decode(str(client_extensions)).decode("utf-8")
                ),
            },
            "displayName": "Serial: "
            + str(serial_number)
            + " "
            + str(datetime.date.today()),
        }

        response = requests.post(
            fido_credentials_endpoint, json=body, headers=headers, verify=False
        )

        if response.status_code == 201:
            create_response = response.json()
            return True, create_response["id"]
        else:
            return False, []

    
    # Function to handle credential creation on YubiKey
    def create_credentials_on_security_key(
        user_id, challenge, user_display_name, user_name
    ):
        """
        Create WebAuthn credentials on a security key (e.g., YubiKey) during the registration process.

        Retrieves the first available CTAP HID device, creates a Fido2Client instance, builds the PublicKeyCredentialCreationOptions
        object, and calls the `make_credential` method to create the credentials on the security key.

        Args:
            user_id (str): The user's ID.
            challenge (str): The challenge string.
            user_display_name (str): The user's display name.
            user_name (str): The user's name.

        Returns:
            tuple: The encoded attestation object, client data, credential ID, and client extension results.
        """
        dev = list(CtapHidDevice.list_devices())[0]

        client = Fido2Client(
            dev,
            "https://login.microsoft.com",
            user_interaction=CliInteraction(),
        )

        pkcco = build_creation_options(challenge, user_id, user_display_name, user_name)

        result = client.make_credential(pkcco["publicKey"])

        attestation_obj = result["attestationObject"]
        attestation = websafe_encode(attestation_obj)

        client_data = result["clientData"].b64

        credential_id = websafe_encode(
            result.attestation_object.auth_data.credential_data.credential_id
        )

        client_extenstion_results = websafe_encode(
            json.dumps(result.attestation_object.auth_data.extensions).encode("utf-8")
        )

        return (
            attestation,
            client_data,
            credential_id,
            client_extenstion_results,
        )

    
    # Function to fetch a Microsoft Entra ID user to be enrolled with a YubiKey
    def get_user_id(user_principal_name, access_token):
        """
        Fetches a Microsoft Entra ID user to be enrolled with a YubiKey.

        This function retrieves a user's profile from the Microsoft Graph API based on the provided User Principal Name (UPN).
        If the UPN is non-existent, it prompts the user to provide a valid UPN until a successful response is received or the
        user cancels the operation.

        Args:
            user_principal_name (str): The User Principal Name of the target user.
            access_token (str): A valid access token for the Microsoft Graph API.

        Returns:
            tuple: A tuple containing the user's profile and the HTTP status code of the response.
        """
        while True:
            headers = set_http_headers(access_token)
            params = {"$select": "id,userPrincipalName,displayName"}
            user_endpoint = (
                "https://graph.microsoft.com/v1.0/users/" + user_principal_name + "/"
            )

            response = requests.get(
                user_endpoint, headers=headers, params=params, verify=False
            )
            status_code = response.status_code

            if (
                status_code == 404
            ):  # If a non-existing UPN was submitted, we expect a 404 error
                click.clear()
                banner()
                user_principal_name = click.prompt("User does not exist. Please try again")
            elif status_code == 200:  # This should be a successful fetch of a user
                user_profile = response.json()
                return user_profile, status_code
            else:
                click.clear()
                banner()
                user_principal_name = click.prompt("An error occurred. Please try again")
                

    # Show banner
    banner()

    # Function to read the YubiKey serial number
    def read_serial_number():
        device = s.single()
        serial_number = device.info.serial      

        # Handle missing Serial Number (e.g., for Security Key Series Consumer Edition)
        if serial_number is None:
            banner()
            click.pause("🛑 This YubiKey DOES NOT have a Serial Number (press any key to exit)")
            click.clear()
            sys.exit(1)
        
        return serial_number


    # Function to check if the serial number is already in the JSON file
    def is_serial_number_in_file(serial_number):
        """
        Check if a serial number is present in the 'output.json' file.

        This function helps avoid programming errors where a user attempts to program a YubiKey that has
        already been programmed. It searches the 'output.json' file for the provided serial number and
        returns True if the serial number is found, False otherwise.

        Args:
            serial_number (str): The serial number to search for in the 'output.json' file.

        Returns:
            bool: True if the serial number is found in the file, False otherwise.
        """
        try:
            with open("output.json", "r") as jsonfile:
                data = json.load(jsonfile)
                for entry in data:
            
                    for item in entry:
                        if item.get("Serial number") == serial_number:
                            return True
        except FileNotFoundError:
            return False
        return False

    # Loop to continuously check for YubiKey
    while True:
        serial_number = read_serial_number()
        if is_serial_number_in_file(serial_number):
            # If the serial number exists in the output.json file, inform the user
            banner()
            click.pause(
                "Insert a new YubiKey and press any key to continue..."
            )
        else:
            # If the serial number does not exist, break the loop
            break
        time.sleep(1)  # Add a short delay to prevent the loop from consuming too much CPU

    # Read the YubiKey serial number (again)
    serial_number = read_serial_number()

    # Generate a random PIN
    pin = generate_random_pin()

    # Now set the PIN on the YubiKey
    set_fido_pin(pin)

    # Prompt for user to provision with YubiKey
    while True:
        click.clear()
        banner()
        user_principal_name = input("Provide User Principal Name (UPN) of target user: ")
        if user_principal_name:  # Check if UPN is not empty
            break
        else:
            click.clear()
            banner()
            click.pause("You did not provide any input (press any key to continue...)")
            

    # Read the user profile returned from Microsoft Graph API
    user_profile, status_code = get_user_id(user_principal_name, access_token)

    # Get FIDO2 credential creation options
    (status, options) = get_fido2_creation_options(user_profile["id"], access_token)

    # Translate attributes to something we can use
    user_name = user_profile["userPrincipalName"]
    user_display_name = user_profile["displayName"]
    user_id = options["publicKey"]["user"]["id"]
    challenge = options["publicKey"]["challenge"]
    challenge_expiry_time = options["challengeTimeoutDateTime"]

    # Create the creential on the YubiKey
    (
        att,
        clientData,
        credId,
        extn,
    ) = create_credentials_on_security_key(
        user_id, challenge, user_display_name, user_name
    )

    # Create the credential in Microsoft Entra ID
    serial_number = read_serial_number()
    activated, auth_method = create_and_activate_fido_method(
        credId,
        extn,
        user_name,
        att,
        clientData,
        serial_number,
        access_token,
    )

    
    # Force PIN change
    banner()
    pin_change = False
    nfc_restricted = False

    
    device = s.single()
    with device.fido() as connection:
        ctap = Ctap2(connection)

        if ctap.info.options.get("setMinPINLength") and click.confirm("Force user to change PIN on first use?", default=True):
            client_pin = ClientPin(ctap)
            token = client_pin.get_pin_token(
                pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG
            )
            config = Config(ctap, client_pin.protocol, token)
            config.set_min_pin_length(force_change_pin=True)

            # Set attribute for JSON output file
            pin_change = True
            banner()
            click.pause(
                "PIN set to expire on first use (press any key to continue...)"
            )

    
        # Enable Secure Transport Mode (restricted NFC)
        banner()
        session = ManagementSession(connection)
        info = session.read_device_info()
        if info.version >= (5, 7) and click.confirm("Configure Secure Transport Mode?", default=True):
            config = DeviceConfig({}, None, None, None)
            config.nfc_restricted = True
            lock_code = None
            
            session.write_device_config(config, False, lock_code)
            # Set attribute for JSON output file
            nfc_restricted = True
            banner()
            click.pause(
                "NFC disabled until powered over USB (press any key to continue...)"
                )


    # Write JSON output file containing relevant attributes
    write_json()

    # Inform user on completion
    banner()
    click.pause(f"Completed configuration for '{user_display_name}' (press any key to continue...)")
    
    

def main():
    while True:
        # Program a YubiKey
        yubikey_eob_registration(Config)

        # Ask the user if they want to program another YubiKey
        banner()
        if not click.confirm("Do you want to enroll another user?", default=False):
            # Exit program in 3 seconds
            for i in range(3, 0, -1):  # Countdown from 3 seconds
                banner()
                click.secho(f"Exiting program in {i} seconds...")
                time.sleep(1)
                click.clear()
            click.clear()
            sys.exit(1)


# Run script
if __name__ == "__main__":
    main()
