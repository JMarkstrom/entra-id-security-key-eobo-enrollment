readme.md

# FIDO2 Enrollment On-Behalf-Of for Microsoft Entra ID 


## ℹ️ About

![](/images/security-key-eobo-with-microsoft-entra-id-integration-overview-diagram.png)

This repository presents a Python script (`sk-entra-id.py`) that facilitates configuration of a YubiKey as well as its assignment to a user in Microsoft **Entra ID**. 
The script is based on **Yubico** proof-of-concept found [here](https://github.com/YubicoLabs/entraId-register-passkeys-on-behalf-of-users) and performs the following configuration tasks:

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


⚠️ This script is provided "as-is" without any warranty of any kind, either expressed or implied.


## 💾 Setup intructions
To install dependencies and configure your Entra ID tenant please see [these](https://github.com/JMarkstrom/entra-id-security-key-obo-enrollment/tree/main/docs) instructions.

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
- ~~Enable "Secure Transport Mode" (restricted NFC) on supported YubiKeys~~
- ~~Handle missing Serial Number (on 'Security Key Series' YubiKey)~~
- Extend an existing output file and handle duplicates
- Offer choice of `.json` _or_ `.csv` as output file format

## 🥷🏻 Contributing
Any help on the above (see 'roadmap) is welcome.

## 📜 Release History
* 2024.08.17 `v1.3` Handle missing Serial Number
* 2024.07.11 `v1.2` Support for [Restricted NFC](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/5.7-firmware-specifics.html#restricted-nfc) 
* 2024.06.15 `v1.1` Updated Graph API endpoints
* 2024.05.04 `v1.0` First release
