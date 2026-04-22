# Active-Directory-Users-Security-Audit
## Active Directory Audit &amp; Recon Tool


A PowerShell-based tool for auditing and reconnaissance of Active Directory environments. Designed for security professionals (red teamers & blue teamers), and system administrators to identify high-risk accounts.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
  - [Recon Modules](#recon-modules)
  - [Audit Modules](#audit-modules)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

- No dependency on the `ActiveDirectory` PowerShell module — uses raw LDAP via .NET `DirectoryServices`
- Works against remote domains with supplied credentials
- Auto-discovers Domain Controllers via DNS SRV records
- Exports all results to timestamped CSV files
- ADAduit_CLM.ps1 is the version to run in CLM (Constrained Language Mode) environment (basically i ran my code through claude to create the CLM version.)


---

## ⚙️ Requirements

| Requirement | Details |
|---|---|
| PowerShell | Version 5.1 or later |
| Network Access | LDAP (port 389) to a Domain Controller |
| Permissions | A valid domain user account (read access is sufficient for most checks) |
| OS | Windows (any version with PowerShell 5.1+) |

---

## 📦 Installation

```powershell
# Clone the repository
git clone https://github.com/MaishaManarat/Active-Directory-Users-Security-Audit.git

# Navigate to the directory
cd Active-Directory-Users-Security-Audit
```

No additional installation steps are needed. The script uses built-in .NET libraries only.

---

## 🚀 Usage

To run Full Language Mode (FLM) evironment- Usually where user has local admin privileges in the device

```powershell
.\ADAudit.ps1
```



To run in Constrained Language Mode (CLM) environment- Usually where user has restrictive privileges
```powershell
.\ADAudit_CLM.ps1
```



You will be prompted interactively to:
1. Choose a mode: `recon` or `audit`
2. Select a specific module (e.g. `a1`, `r2`, or `all`)
3. Enter the target domain name (e.g. `corp.local`)
4. Optionally specify a Domain Controller
5. Enter credentials for authentication

---

## 📂 Modules

### Recon Modules

| ID | Name | Description |
|---|---|---|
| `r1` | **User Info** | Retrieves detailed information about a specific domain user |
| `r2` | **SID Translator** | Resolves an on-premises SID to a user account |
| `r3` | **User Dump** | Exports all domain user accounts with key attributes to CSV |

### Audit Modules

| ID | Name | What It Checks |
|---|---|---|
| `a1` | **Admin Accounts** | Members of Domain Admins, Enterprise Admins, Administrators, and Schema Admins |
| `a2` | **DCSync Privileges** | Accounts with `DS-Replication-Get-Changes` or `DS-Replication-Get-Changes-All` rights on the domain object |
| `a3` | **Service Accounts** | User accounts with the "Password Never Expires" flag set |
| `a4` | **Dormant Accounts** | Enabled accounts with no login activity beyond a configurable threshold |
| `a5` | **Stale Accounts** | Enabled accounts whose password has not been changed within a configurable period |
| `a6` | **Unconstrained Delegation** | User accounts trusted for unconstrained Kerberos delegation |
| `a7` | **Kerberoastable Accounts** | Enabled user accounts with a registered Service Principal Name (SPN) |
| `all` | **Full Audit** | Runs all audit modules (a1 through a7) sequentially |

---

## 📁 Output

All results are saved as CSV files in the configured output directory. Files are named with the domain name and a timestamp to avoid overwrites.




## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome.

Please open an issue first for major changes to discuss what you'd like to change.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 👤 Author

Made by [Maisha Manarat](https://github.com/MaishaManarat)

