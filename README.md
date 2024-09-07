# FIDO2 Enrollment On-Behalf-Of for Microsoft Entra ID 

![](/images/security-key-eobo-with-microsoft-entra-id-integration-overview-diagram.png)

## ℹ️ About
This repository presents a Python script (`sk-entra-id.py`) that facilitates configuration of a YubiKey as well as its assignment to a user in Microsoft **Entra ID**. 
The script is based on **Yubico** Proof-of-Concept found [here](https://github.com/YubicoLabs/entraId-register-passkeys-on-behalf-of-users) and performs the following configuration tasks:

### Script feature summary

| Script Feature        | Explanation           | Comment  |
|:------------- |:-------------|:-----|
| User gestures | _The script will prompt for necessary interactions (remove, insert, touch)._     |    |
| Reset YubiKey    | _The YubiKey is factory reset prior to configuration._ |  |
| Set random PIN    | _A random non-trivial PIN* is set on the YubiKey._      |_Configurable_ |
| Enroll passkey    | _A FIDO2 credential is created on-behalf-of the user._      |    |
| Force PIN change | _The configured PIN must be changed by the end-user._     |   FW ```5.7``` _or later_|
| Restrict NFC | _NFC access to the YubiKey is limited until first use._     |   FW ```5.7``` _or later_ |
| Prompt next user | _On successful configuration the script will prompt to continue._     |    |
| Save to file | _All relevant configuration items are saved to a JSON output file._     |    |

*PIN is set to ```4``` characters. If you are programming _Enterprise Edition_ Security Keys you will need to set it to ```6```

```python
# Set variable to control PIN length
pin_length = 6

```

## ⚠️ Disclaimer
The script provided herein is made available on an "as-is" basis, without any warranties or representations, whether express, implied, or statutory, including but not limited to implied warranties of merchantability, fitness for a particular purpose, or non-infringement.

The user acknowledges that, as of the date of publication (H2 2024), the features upon which this script relies are in a Preview phase as provided by Microsoft. As such, these features are subject to change, modification, or discontinuation at any time without notice and may be unsupported. The user assumes all risks associated with the use of the script and the underlying features. The provider of this script disclaims any liability for damages, losses, or other claims arising from or in connection with the use or reliance on this script.


## 💾 Setup intructions
To install dependencies and configure your Entra ID tenant please follow instructions [here](https://github.com/JMarkstrom/entra-id-security-key-obo-enrollment/tree/main/docs).

## 📖 Usage
To run the script, simply execute command: `python sk-entra-id.py`

![](/images/security-key-eobo-with-microsoft-entra-id.1.2.gif)

**NOTE**: Refer to [swjm.blog](https://swjm.blog) for _detailed_ usage instructions.


## 🗎 The output.json file
The script will outout a file on working directory called `output.json`. 

Here is an example: 

```bash
[
    [
        {
            "Name": "Alice Smith",
            "UPN": "alice@swjm.blog",
            "Model": "YubiKey 5 NFC",
            "Serial number": 12345678,
            "PIN": "5144",
            "PIN change required": false
            "Secure Transport Mode": false
        }
    ],
    [
        {
            "Name": "Mike Smith",
            "UPN": "mike@swjm.blog",
            "Model": "YubiKey 5C NFC",
            "Serial number": 87654321,
            "PIN": "6855",
            "PIN change required": true
            "Secure Transport Mode": true
        }
    ]
]
```

## 📖 Roadmap
Possible improvements includes:
- Extend an existing output file and handle duplicates
- Offer choice of `.json` _or_ `.csv` as output file format

## 🥷🏻 Contributing
Any help on the above (see 'roadmap) is welcome.

## 📜 Release History
* 2024.08.17 `v1.3`
