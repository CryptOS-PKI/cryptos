# Distribute the root with Group Policy

Domain members trust a CryptOS-issued certificate once the CryptOS root is in
their Trusted Root Certification Authorities store. A Group Policy Object (GPO)
puts it there on every computer in the GPO's scope, so nobody adds the root by
hand. Once the policy has applied, a domain controller's LDAPS and KDC
certificates from [`active-directory.md`](active-directory.md), and any other
certificate the hierarchy issues, validate on those computers.

The examples use the domain `ad.example.org`, a root named
`Example Root CA G1` saved as `root.cer`, and an issuing CA certificate saved
as `issuing.cer`. `root.cer` can be DER or Base64 (PEM).

> [!CAUTION]
> **Distribute only a root you control.** Every computer the GPO applies to
> will trust every certificate that root signs, for any name. **Never push a
> test or lab root to production clients**: link a lab root's GPO only in the
> lab domain. If a root was pushed by mistake, remove the GPO (or its link) and
> run `gpupdate /force`; the computers drop the root at their next refresh.

Before you start, you need:

- an account that can create GPOs and link them where you want them, such as
  a member of Domain Admins;
- the Group Policy Management Console and the `GroupPolicy` PowerShell module.
  Both are on every domain controller; on Windows Server add the Group Policy
  Management feature, and on Windows client add the RSAT Group Policy
  Management Tools.

## With the Group Policy Management Console

1. Open **Group Policy Management** (`gpmc.msc`).
2. Expand **Forest > Domains**, right-click `ad.example.org` (or an OU), and
   choose **Create a GPO in this domain, and Link it here**. Name it, for
   example, `CryptOS root trust`.
3. Right-click the new GPO and choose **Edit**.
4. Go to **Computer Configuration > Policies > Windows Settings > Security
   Settings > Public Key Policies > Trusted Root Certification Authorities**.
5. Right-click **Trusted Root Certification Authorities**, choose **Import**,
   pick `root.cer`, keep the store the wizard offers (Trusted Root
   Certification Authorities), and finish.
6. Optional: under **Public Key Policies > Intermediate Certification
   Authorities**, import `issuing.cer` the same way. You can skip this if the
   computers can reach the issuing CA's AIA caIssuers URL (under the node's
   `revocation_base_url`); Windows then fetches the issuing CA certificate
   itself.

> [!TIP]
> To try the policy on a few computers first, link the GPO to an OU that holds
> only those computers, and link it to the domain when it works.

## With PowerShell

There is no cmdlet that imports a certificate into a GPO. The Trusted Root
policy is a registry value, a certificate blob under
`HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates\<SHA-1 thumbprint>`,
so the script below gets that blob by importing `root.cer` into a temporary
certificate store, writes it into a new GPO, and links the GPO. The temporary
store is not a trusted store and is deleted straight away. Run it in an
elevated PowerShell on a domain controller or a computer with the Group Policy
tools:

**Windows (PowerShell)**

```powershell
Import-Module GroupPolicy
$gpo  = 'CryptOS root trust'
$link = 'DC=ad,DC=example,DC=org'

New-Item -Path Cert:\LocalMachine\CryptOSGpo | Out-Null
$cert = Import-Certificate -FilePath .\root.cer -CertStoreLocation Cert:\LocalMachine\CryptOSGpo
$t    = $cert.Thumbprint
$blob = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SystemCertificates\CryptOSGpo\Certificates\$t").Blob
Remove-Item -Path Cert:\LocalMachine\CryptOSGpo -Recurse

New-GPO -Name $gpo | Out-Null
Set-GPRegistryValue -Name $gpo `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates\$t" `
  -ValueName Blob -Type Binary -Value $blob | Out-Null
New-GPLink -Name $gpo -Target $link | Out-Null
```

To link to an OU instead, set `$link` to its distinguished name, for example
`OU=Servers,DC=ad,DC=example,DC=org`.

> [!CAUTION]
> Import into a new, empty store as above, not into
> `Cert:\LocalMachine\Root`. When the computer already trusts the root through
> Group Policy, `Import-Certificate` into `Root` writes nothing to the local
> registry store, so there is no blob to read.

### `certutil -dspublish` is not a GPO

`certutil -dspublish -f root.cer RootCA` (see
[Trusting the chain](active-directory.md#trusting-the-chain)) also gets the
root onto domain members, but it publishes the root to Active Directory, in the
forest's Configuration partition, not to a GPO. Every Windows computer in the
**whole forest** then trusts it at its next policy refresh. You cannot scope it
to an OU or filter it, it does not show in `gpresult`, and it appears on
members under `certutil -enterprise -store root`, not the Group Policy store.
Use a GPO when you want to control which computers trust the root.

## Check that the policy applied

On a computer in the GPO's scope, refresh the computer policy and list the
applied GPOs:

**Windows (PowerShell)**

```powershell
gpupdate /target:computer /force
gpresult /scope computer /r
```

> [!TIP]
> `CryptOS root trust` appears under **Applied Group Policy Objects** in the
> Computer Settings part of the output. Without `gpupdate`, the policy arrives
> at the next background refresh, about every 90 minutes.

Then check that the root is in the store Group Policy fills:

**Windows (PowerShell)**

```powershell
certutil -grouppolicy -store root
Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -like '*Example Root CA G1*'
```

> [!TIP]
> Both list `Example Root CA G1`. Plain `certutil -store root` shows only roots
> added on the computer itself, so it does not list a root that came from the
> GPO. `Get-ChildItem Cert:\LocalMachine\Root` and the Certificates snap-in
> (`certlm.msc`) show both kinds.

Finally, check that a CryptOS-issued chain validates with the root present only
through the GPO, for example with a domain controller's LDAPS certificate:

**Windows (PowerShell)**

```powershell
certutil -verify -urlfetch dc01-ldaps.cer
```

> [!TIP]
> Every chain element ends with `dwErrorStatus=0`, and the output ends with
> `Leaf certificate revocation check passed`. If you added the root by hand
> earlier, remove that copy first (`certutil -delstore root <thumbprint>`) so
> the check proves the GPO works on its own.
