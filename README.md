# FIDO2 Enrollment On-Behalf-Of for Microsoft Entra ID 

![](/images/security-key-eobo-with-microsoft-entra-id-integration-overview-diagram.png)

## ℹ️ About
This repository presents a Python script (`sk-entra-id.py`) that facilitates configuration of a YubiKey as well as its assignment to a user in Microsoft **Entra ID**. 
The script is based on a **Yubico** Proof-of-Concept found [here](https://github.com/YubicoLabs/entraId-register-passkeys-on-behalf-of-users) and performs the following configuration tasks:

### Script feature summary

| Script Feature        | Explanation           | Comment  |
|:------------- |:-------------|:-----|
| User gestures | _The script will prompt for necessary interactions (remove, insert, touch)._     |    |
| Reset YubiKey    | _The YubiKey is factory reset prior to configuration._ |  |
| Set random PIN    | _A random non-trivial PIN* is set on the YubiKey._      |_Configurable_ |
| Enroll passkey    | _A FIDO2 credential is created on-behalf-of the user._      |    |
| Set minimum PIN length | _Any new PIN must comply with length requirement._     |   FW ```5.7``` _or later_|
| Force PIN change | _The configured PIN must be changed by the end-user._     |   FW ```5.7``` _or later_|
| Restrict NFC | _NFC access to the YubiKey is limited until first use._     |   FW ```5.7``` _or later_ |
| Prompt next user | _On successful configuration the script will prompt to continue._     |    |
| Save to file | _All relevant configuration items are saved to a CSV output file._     |    |

*PIN length is set to ```4```. If you are enrolling _Enterprise Edition_ Security Keys _or_ if you wish to enforce longer PINs, you must adjust this value.

```python
# Set variable to control PIN length
pin_length = 4

```

## ⚠️ Disclaimer
This application is provided on an “AS IS” basis, without warranties or representations of any kind. For the complete warranty disclaimer and terms governing use, modification, and redistribution, see the [BSD-2-Clause License](LICENSE).

## 💾 Setup intructions
To install dependencies and configure your Entra ID tenant please follow instructions [here](https://github.com/JMarkstrom/entra-id-security-key-obo-enrollment/tree/main/docs).

## 📖 Usage
To run the script, simply execute command: `python sk-entra-id.py`

![](/images/security-key-eobo-with-microsoft-entra-id.1.2.gif)


## 🗎 Results
The script will output a file on working directory called `output.csv`. 

Here is an example:   

```csv
Name,UPN,Model,Serial number,PIN,PIN change required,Secure Transport Mode
Alice Smith,alice@swjm.blog,YubiKey 5C NFC,15898933,5144,True,True
Bob Smith,bob@swjm.blog,YubiKey 5C NFC,17735649,4060,False,False
```

In Microsoft Entra ID the registered security key will appear with it's associated Serial Number:

![](/images/security-key-eobo-with-microsoft-entra-id-added-to-account.png)

## 🥷🏻 Contributing
You can help by getting involved in the project, _or_ by donating (any amount!).   
Donations will support costs such as domain registration and code signing (planned).

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/donate/?business=RXAPDEYENCPXS&no_recurring=1&item_name=Help+cover+costs+of+the+SWJM+blog+and+app+code+signing%2C+supporting+a+more+secure+future+for+all.&currency_code=USD)

## 📜 Release History
* 2025.03.06 `v1.5` Now outputs CSV instead of JSON
* 2024.11.30 `v1.4` Misc. improvements
* 2024.08.17 `v1.3` MVP release

## ™️ Trademark notice
YubiKey is a trademark of Yubico. This project is independent of and is not affiliated with, endorsed by, or sponsored by Yubico.

## ⚖️ License
This software is licensed under the [BSD-2-Clause License](LICENSE).   
Copyright (c) 2026 swjm.blog.


