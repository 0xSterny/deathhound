package library

import (
	"fmt"
)

// NamedQuery represents a pre-defined Cypher query
type NamedQuery struct {
	Name        string
	Description string
	Category    string
	Cypher      string
}

// Queries is the map of all available named queries
var Queries = map[string]NamedQuery{
	"accounts-related-to-aad-entra-connect": {
		Name:        "Accounts related to AAD Entra Connect",
		Description: "Query to start reconnaissance about AADConnect / Entra Connect related accounts",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (u) 
WHERE (u:User OR u:AZUser) 
AND (u.name =~ '(?i)^MSOL_|.*AADConnect.*|.*ADSyncMSA.*|.*AAD_.*|.*PROVAGENTGMSA.*' 
OR u.userprincipalname =~ '(?i)^sync_.*') 
RETURN u
`,
	},
	"accounts-with-clear-text-password-attributes": {
		Name:        "Accounts with clear-text password attributes",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE n.userpassword IS NOT NULL
OR n.unixpassword IS NOT NULL
OR n.unicodepwd IS NOT NULL
OR n.msSFU30Password IS NOT NULL
RETURN n
`,
	},
	"accounts-with-sid-history": {
		Name:        "Accounts with SID History",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(:Base)-[:HasSIDHistory]->(:Base)
RETURN p
`,
	},
	"accounts-with-sid-history-to-a-non-existent-domain": {
		Name:        "Accounts with SID History to a non-existent domain",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (d:Domain)
WITH collect(d.objectid) AS domainSIDs
MATCH p=(n:Base)-[:HasSIDHistory]->(m:Base)
WHERE NOT n.domainsid IN domainSIDs
RETURN p
`,
	},
	"accounts-with-sid-history-to-a-same-domain-account": {
		Name:        "Accounts with SID History to a same-domain account",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Base)-[:HasSIDHistory]->(m:Base)
WHERE n.domainsid = m.domainsid
RETURN p
`,
	},
	"accounts-with-smart-card-required-in-domains-where-smart-account-passwords-do-not-expire": {
		Name:        "Accounts with smart card required in domains where smart account passwords do not expire",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(s:Domain)-[:Contains*1..]->(t:Base)
WHERE s.expirepasswordsonsmartcardonlyaccounts = false
AND t.enabled = true
AND t.smartcardrequired = true
RETURN p
`,
	},
	"accounts-with-weak-password-storage-encryption": {
		Name:        "Accounts with weak password storage encryption",
		Description: "Accounts with passwords set before the existence of Windows Server 2008 Domain Controller which therefore lack AES encryption keys.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE n.pwdlastset < 1204070400 // Password Last Set before Windows Server 2008 release
RETURN n
LIMIT 100
`,
	},
	"aces-across-trusts": {
		Name:        "ACEs across trusts",
		Description: "ACEs granted across a trust, the ACEs are set on trusting objects and the rights are granted to objects from trusted domains.",
		Category:    "Domain Information",
		Cypher: `
MATCH p=(trustedDomainPrincipal:Base)-[r]->(trustingDomainPrincipal:Base)
WHERE trustedDomainPrincipal.domainsid <> trustingDomainPrincipal.domainsid
AND r.isacl
RETURN p
LIMIT 1000
`,
	},
	"adminsdholder-protected-accounts-and-groups": {
		Name:        "AdminSDHolder protected Accounts and Groups",
		Description: "Objects whose permissions are set by SDProp to the template AdminSDHolder object as per MS-ADTS 3.1.1.6.1.2 Protected Objects. Does not exclude objects if specified in dSHeuristics dwAdminSDExMask",
		Category:    "Domain Information",
		Cypher: `
MATCH (n:Base)-[:MemberOf*0..]->(m:Group)
WHERE (
  n.objectid =~ ".*-(S-1-5-32-544|S-1-5-32-548|S-1-5-32-549|S-1-5-32-550|S-1-5-32-551|S-1-5-32-552|518|512|519)$" // Groups
  OR m.objectid =~ ".*-(S-1-5-32-544|S-1-5-32-548|S-1-5-32-549|S-1-5-32-550|S-1-5-32-551|S-1-5-32-552|518|512|519)$" // Members of groups
  OR n.objectid =~ ".*-(500|502|516|521)$" // Direct objects
)
RETURN n
`,
	},
	"adminsdholder-to-protected-objects-relationship": {
		Name:        "AdminSDHolder to protected objects relationship",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n)-[:ProtectAdminGroups]->(m)
RETURN p
LIMIT 1000
`,
	},
	"all-adcs-esc-privilege-escalation-edges": {
		Name:        "All ADCS ESC privilege escalation edges",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p=(:Base)-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|GoldenCert|CoerceAndRelayNTLMToADCS]->(:Base)
RETURN p
`,
	},
	"all-coerce-and-ntlm-relay-edges": {
		Name:        "All coerce and NTLM relay edges",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH p = (n:Base)-[:CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToSMB]->(:Base)
RETURN p LIMIT 500
`,
	},
	"all-dnsadmins": {
		Name:        "All DNSAdmins",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p=(n:Base)-[:MemberOf]->(g:Group) 
WHERE n.name STARTS WITH "DNSADMINS@"
RETURN p
`,
	},
	"all-domain-admins": {
		Name:        "All Domain Admins",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p = (t:Group)<-[:MemberOf*1..]-(a)
WHERE (a:User or a:Computer) and t.objectid ENDS WITH '-512'
RETURN p
LIMIT 1000
`,
	},
	"all-global-administrators": {
		Name:        "All Global Administrators",
		Description: "",
		Category:    "General",
		Cypher: `
MATCH p=(:AZBase)-[:AZHasRole*1..]->(t:AZRole)
WHERE t.name =~ '(?i)Global Administrator.*'
RETURN p
LIMIT 1000
`,
	},
	"all-gpos-applied-to-a-specific-computer": {
		Name:        "All GPOs applied to a specific Computer",
		Description: "View all GPOs that are applied to any specific computer. This query identifies GPOs that are applied at both the Domain Level and the OU level, saving time in large Active Directory environments where GPO inheritance is complex. Replace \"COMPUTER_NAME\" with the target computer name or a substring. Note this does not take OU 'Block inheritance' and GPO 'No Override' into account.",
		Category:    "Domain Information",
		Cypher: `
// Replace "HOSTNAME/FQDN" with the computer's
MATCH p=(c:Computer)<-[:Contains*..]-(:Base)<-[:GPLink]-(:GPO)
WHERE toLower(c.name) CONTAINS toLower("HOSTNAME/FQDN")
RETURN p
`,
	},
	"all-incoming-and-local-paths-for-a-specific-computer": {
		Name:        "All incoming and local paths for a specific computer",
		Description: "All incoming and local paths for a specific computer; incoming from domain objects and paths local inside the computer.",
		Category:    "Domain Information",
		Cypher: `
// Replace 'HOSTNAME' with the computer's shortname eg. 'SRV01', not FQDN
MATCH p=(n:Base)-[:RemoteInteractiveLogonRight|AdminTo|CanRDP|LocalToComputer|MemberOfLocalGroup]-(m:Base)
WHERE m.name CONTAINS 'HOSTNAME'
AND m.name CONTAINS '.' // Only see computer-related objects (eg. not AD Groups)
RETURN p
`,
	},
	"all-kerberoastable-users": {
		Name:        "All Kerberoastable users",
		Description: "",
		Category:    "Kerberos Interaction",
		Cypher: `
MATCH (u:User)
WHERE u.hasspn=true
AND u.enabled = true
AND NOT u.objectid ENDS WITH '-502'
AND NOT COALESCE(u.gmsa, false) = true
AND NOT COALESCE(u.msa, false) = true
RETURN u
LIMIT 100
`,
	},
	"all-members-of-high-privileged-roles": {
		Name:        "All members of high privileged roles",
		Description: "",
		Category:    "General",
		Cypher: `
MATCH p=(t:AZRole)<-[:AZHasRole|AZMemberOf*1..2]-(:AZBase)
WHERE t.name =~ '(?i)Global Administrator|User Administrator|Cloud Application Administrator|Authentication Policy Administrator|Exchange Administrator|Helpdesk Administrator|Privileged Authentication Administrator|Privileged Role Administrator'
RETURN p
LIMIT 1000
`,
	},
	"all-operators": {
		Name:        "All Operators",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p=(:Base)-[:MemberOf]->(n:Group)
WHERE (
  n.objectid ENDS WITH 'S-1-5-32-551' OR // Backup Operators
  n.objectid ENDS WITH 'S-1-5-32-556' OR // Network Configuration Operators
  n.objectid ENDS WITH 'S-1-5-32-549' OR // Server Operators
  n.objectid ENDS WITH 'S-1-5-32-579' OR // Access Control Assistance Operators
  n.objectid ENDS WITH 'S-1-5-32-548' OR // Account Operators
  n.objectid ENDS WITH 'S-1-5-32-569' OR // Cryptographic Operators
  n.objectid ENDS WITH 'S-1-5-32-550' // Print Operators
)
RETURN p
`,
	},
	"all-paths-crossing-a-specific-trust": {
		Name:        "All paths crossing a specific trust",
		Description: "All paths crossing a specific trust from a trusted to a trusting domain.",
		Category:    "Domain Information",
		Cypher: `
// Replace the TRUSTED domain SID
// Replace the TRUSTING domain SID
MATCH p=(Trusted:Base)-[:AD_ATTACK_PATHS]->(Trusting:Base)
WHERE Trusted.domainsid = 'S-1-5-21-1111111111-1111111111-1111111111'
AND Trusting.domainsid = 'S-1-5-21-2222222222-2222222222-2222222222'
RETURN p
LIMIT 1000
`,
	},
	"all-schema-admins": {
		Name:        "All Schema Admins",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p=(n:Base)-[:MemberOf*1..]->(m:Group)
WHERE (n:User OR n:Computer)
AND m.objectid ENDS WITH "-518" // Schema Admins
RETURN p
`,
	},
	"all-service-principals-with-microsoft-graph-app-role-assignments": {
		Name:        "All service principals with Microsoft Graph App Role assignments",
		Description: "",
		Category:    "Microsoft Graph",
		Cypher: `
MATCH p=(:AZServicePrincipal)-[:AZMGAppRoleAssignment_ReadWrite_All|AZMGApplication_ReadWrite_All|AZMGDirectory_ReadWrite_All|AZMGGroupMember_ReadWrite_All|AZMGGroup_ReadWrite_All|AZMGRoleManagement_ReadWrite_Directory|AZMGServicePrincipalEndpoint_ReadWrite_All]->(:AZServicePrincipal)
RETURN p
LIMIT 1000
`,
	},
	"all-service-principals-with-microsoft-graph-privilege-to-grant-arbitrary-app-roles": {
		Name:        "All service principals with Microsoft Graph privilege to grant arbitrary App Roles",
		Description: "",
		Category:    "Microsoft Graph",
		Cypher: `
MATCH p=(:AZServicePrincipal)-[:AZMGGrantAppRoles]->(:AZTenant)
RETURN p
LIMIT 1000
`,
	},
	"as-rep-roastable-tier-zero-users-dontreqpreauth": {
		Name:        "AS-REP Roastable Tier Zero users (DontReqPreAuth)",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND n.dontreqpreauth = true
RETURN n
`,
	},
	"as-rep-roastable-users-dontreqpreauth": {
		Name:        "AS-REP Roastable users (DontReqPreAuth)",
		Description: "",
		Category:    "Kerberos Interaction",
		Cypher: `
MATCH (u:User)
WHERE u.dontreqpreauth = true
AND u.enabled = true
RETURN u
LIMIT 100
`,
	},
	"ca-administrators-and-ca-managers": {
		Name:        "CA administrators and CA managers",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:ManageCertificates|ManageCA]->(:EnterpriseCA)
RETURN p
LIMIT 1000
`,
	},
	"ca-administrators-and-ca-managers-esc7": {
		Name:        "CA Administrators and CA Managers (ESC7)",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:ManageCertificates|ManageCA]->(:EnterpriseCA)
RETURN p
LIMIT 1000
`,
	},
	"circular-ad-group-memberships": {
		Name:        "Circular AD group memberships",
		Description: "Detects circular group membership chains where groups are members of themselves through one or more intermediate groups. This causes an administrative complexity.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(x:Group)-[:MemberOf*2..]->(y:Group)
WHERE x.objectid=y.objectid
RETURN p
LIMIT 100
`,
	},
	"circular-az-group-memberships": {
		Name:        "Circular AZ group memberships",
		Description: "Detects circular group membership chains where groups are members of themselves through one or more intermediate groups. This causes an administrative complexity.",
		Category:    "Azure Hygiene",
		Cypher: `
MATCH p=(x:AZGroup)-[:AZMemberOf*2..]->(y:AZGroup)
WHERE x.objectid=y.objectid
RETURN p
LIMIT 100
`,
	},
	"collection-health-of-ca-registry-data": {
		Name:        "Collection health of CA Registry Data",
		Description: "BloodHound's ADCS analysis requires collecting CA registry data to increase accuracy/enable more edges. Collection by default requires SharpHound has Administrators membership. Requires SharpHound v2.3.5 or above. It only requires one misconfigured CA to potentially a full forest compromise by any principal. CAs returned by this query have not been collected.",
		Category:    "Domain Information",
		Cypher: `
MATCH p=(eca:EnterpriseCA)<-[:HostsCAService]-(c:Computer)
WHERE (
  eca.isuserspecifiessanenabledcollected = false
  OR eca.casecuritycollected = false
  OR eca.enrollmentagentrestrictionscollected = false
  OR eca.roleseparationenabledcollected = false
)
// Exclude inactive CAs
AND c.enabled = true
AND c.lastlogontimestamp > (datetime().epochseconds - (30 * 86400))
RETURN p
`,
	},
	"collection-health-of-dc-registry-data": {
		Name:        "Collection health of DC Registry Data",
		Description: "BloodHound's ADCS analysis requires collecting CA registry data to increase accuracy/enable more edges. Collection by default requires SharpHound has Administrators membership. Requires SharpHound v2.3.5 or above. It only requires one misconfigured DC to potentially a full forest compromise by any principal. DCs returned by this query have not been collected.",
		Category:    "Domain Information",
		Cypher: `
MATCH p=(:Domain)<-[:DCFor]-(c:Computer)
WHERE c.strongcertificatebindingenforcementraw IS NULL
// Exclude inactive DCs
AND c.enabled = true
AND c.lastlogontimestamp > (datetime().epochseconds - (30 * 86400))
RETURN p
`,
	},
	"compromising-permissions-on-adcs-nodes-esc5": {
		Name:        "Compromising permissions on ADCS nodes (ESC5)",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (n:Base)-[:Owns|WriteOwner|WriteDacl|GenericAll|GenericWrite]->(m:Base)
WHERE m.distinguishedname CONTAINS "PUBLIC KEY SERVICES"
AND NOT n.objectid ENDS WITH "-512" // Domain Admins
AND NOT n.objectid ENDS WITH "-519" // Enterprise Admins
AND NOT n.objectid ENDS WITH "-544" // Administrators
RETURN p
LIMIT 1000
`,
	},
	"computer-owners-who-can-obtain-laps-passwords": {
		Name:        "Computer owners who can obtain LAPS passwords",
		Description: "Creators of computer objects get abusable rights on the computer object. If the owner is not explicitly granted ReadLAPSPassword they can still compromise the computer with the abusable owner rights.",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p = (c:Computer)<-[:GenericAll|Owns|WriteDacl|WriteOwner|AllExtendedRights]-(n:User)
WHERE c.haslaps = true AND c.ownersid = n.objectid
RETURN p
`,
	},
	"computers-not-requiring-inbound-smb-signing": {
		Name:        "Computers not requiring inbound SMB signing",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH (n:Computer)
WHERE n.smbsigning = False
RETURN n
`,
	},
	"computers-where-domain-users-are-local-administrators": {
		Name:        "Computers where Domain Users are local administrators",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(s:Group)-[:AdminTo]->(:Computer)
WHERE s.objectid ENDS WITH '-513'
RETURN p
LIMIT 1000
`,
	},
	"computers-where-domain-users-can-read-laps-passwords": {
		Name:        "Computers where Domain Users can read LAPS passwords",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(s:Group)-[:AllExtendedRights|ReadLAPSPassword]->(:Computer)
WHERE s.objectid ENDS WITH '-513'
RETURN p
LIMIT 1000
`,
	},
	"computers-with-membership-in-protected-users": {
		Name:        "Computers with membership in Protected Users",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH p = (:Base)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-525'
RETURN p LIMIT 1000
`,
	},
	"computers-with-non-default-primary-group-membership": {
		Name:        "Computers with non-default Primary Group membership",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Computer)-[r:MemberOf]->(g:Group)
WHERE NOT g.objectid ENDS WITH "-515" // Domain Computers
AND NOT n.isdc = true
AND NOT n.isreadonlydc = true
AND r.isprimarygroup = true
RETURN p
`,
	},
	"computers-with-passwords-older-than-the-default-maximum-password-age": {
		Name:        "Computers with passwords older than the default maximum password age",
		Description: "Machine account passwords are regularly changed for security purposes. Starting with Windows 2000-based computers, the machine account password automatically changes every 30 days.",
		Category:    "Active Directory Hygiene",
		Cypher: `
WITH 60 as rotation_period
MATCH (n:Computer)
WHERE n.pwdlastset < (datetime().epochseconds - (rotation_period * 86400)) // password not rotated
AND n.enabled = true // enabled computers
AND n.whencreated < (datetime().epochseconds - (rotation_period * 86400)) // exclude recently created computers
AND n.lastlogontimestamp > (datetime().epochseconds - (rotation_period * 86400)) // active computers (Replicated value)
AND n.lastlogon > (datetime().epochseconds - (rotation_period * 86400)) // active computers (Non-replicated value)
RETURN n
`,
	},
	"computers-with-the-outgoing-ntlm-setting-set-to-deny-all": {
		Name:        "Computers with the outgoing NTLM setting set to Deny all",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH (c:Computer)
WHERE c.restrictoutboundntlm = True
RETURN c LIMIT 1000
`,
	},
	"computers-with-the-webclient-running": {
		Name:        "Computers with the WebClient running",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH (c:Computer)
WHERE c.webclientrunning = True
RETURN c LIMIT 1000
`,
	},
	"computers-with-unsupported-operating-systems": {
		Name:        "Computers with unsupported operating systems",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (c:Computer)
WHERE c.operatingsystem =~ '(?i).*Windows.* (2000|2003|2008|2012|xp|vista|7|8|me|nt).*'
RETURN c
LIMIT 100
`,
	},
	"computers-without-windows-laps": {
		Name:        "Computers without Windows LAPS",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (c:Computer)
WHERE c.operatingsystem =~ '(?i).*WINDOWS (SERVER)? ?(10|11|2019|2022|2025).*'
AND c.haslaps = false
AND c.enabled = true
RETURN c
LIMIT 100
`,
	},
	"cross-forest-trusts-with-abusable-configuration": {
		Name:        "Cross-forest trusts with abusable configuration",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Domain)-[:CrossForestTrust|SpoofSIDHistory|AbuseTGTDelegation]-(m:Domain)
WHERE (n)-[:SpoofSIDHistory|AbuseTGTDelegation]-(m)
RETURN p
`,
	},
	"dangerous-privileges-for-domain-users-groups": {
		Name:        "Dangerous privileges for Domain Users groups",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(s:Group)-[r:AD_ATTACK_PATHS]->(:Base)
WHERE s.objectid ENDS WITH '-513'
AND NOT r:MemberOf
RETURN p
LIMIT 1000
`,
	},
	"dcs-vulnerable-to-ntlm-relay-to-ldap-attacks": {
		Name:        "DCs vulnerable to NTLM relay to LDAP attacks",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH p = (dc:Computer)-[:DCFor]->(:Domain)
WHERE (dc.ldapavailable = True AND dc.ldapsigning = False)
OR (dc.ldapsavailable = True AND dc.ldapsepa = False)
OR (dc.ldapavailable = True AND dc.ldapsavailable = True AND dc.ldapsigning = False and dc.ldapsepa = True)
RETURN p
`,
	},
	"devices-with-unsupported-operating-systems": {
		Name:        "Devices with unsupported operating systems",
		Description: "",
		Category:    "Azure Hygiene",
		Cypher: `
MATCH (n:AZDevice)
WHERE n.operatingsystem CONTAINS 'WINDOWS'
AND n.operatingsystemversion =~ '(10.0.19044|10.0.22000|10.0.19043|10.0.19042|10.0.19041|10.0.18363|10.0.18362|10.0.17763|10.0.17134|10.0.16299|10.0.15063|10.0.14393|10.0.10586|10.0.10240|6.3.9600|6.2.9200|6.1.7601|6.0.6200|5.1.2600|6.0.6003|5.2.3790|5.0.2195).?.*'
RETURN n
LIMIT 100
`,
	},
	"direct-principal-rights-assignment": {
		Name:        "Direct Principal Rights Assignment",
		Description: "This query identifies rights assigned directly to users or computers instead of groups. Active Directory best practice requires granting rights to groups, then adding users as group members. This role-based access control (RBAC) approach ensures permissions are easily auditable and manageable. Results include inherited rights, which must be modified at the parent container level.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Base)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|AllowedToDelegate|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->(:Base)
WHERE (n:User OR n:Computer)  
RETURN p
LIMIT 1000
`,
	},
	"disabled-tier-zero-/-high-value-principals": {
		Name:        "Disabled Tier Zero / High Value principals",
		Description: "",
		Category:    "Azure Hygiene",
		Cypher: `
MATCH (n:AZBase)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND n.enabled = false
RETURN n
LIMIT 100
`,
	},
	"domain-admins-logons-to-non-domain-controllers": {
		Name:        "Domain Admins logons to non-Domain Controllers",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH (s)-[:MemberOf*0..]->(g:Group)
WHERE g.objectid ENDS WITH '-516'
WITH COLLECT(s) AS exclude
MATCH p = (c:Computer)-[:HasSession]->(:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512' AND NOT c IN exclude
RETURN p
LIMIT 1000
`,
	},
	"domain-controllers-allowing-ntlmv1-or-lm-authentication": {
		Name:        "Domain Controllers allowing NTLMv1 or LM authentication",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH (dc:Computer)
WHERE dc.isdc = true
AND (dc.lmcompatibilitylevel IS NOT NULL AND NOT dc.lmcompatibilitylevel = 5)
RETURN dc
`,
	},
	"domain-controllers-with-upn-certificate-mapping-enabled": {
		Name:        "Domain controllers with UPN certificate mapping enabled",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (s:Computer)-[:DCFor]->(:Domain)
WHERE s.certificatemappingmethodsraw IN [4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]
RETURN p
LIMIT 1000
`,
	},
	"domain-controllers-with-weak-certificate-binding-enabled": {
		Name:        "Domain controllers with weak certificate binding enabled",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (s:Computer)-[:DCFor]->(:Domain)
WHERE s.strongcertificatebindingenforcementraw = 0 OR s.strongcertificatebindingenforcementraw = 1
RETURN p
LIMIT 1000
`,
	},
	"domain-migration-groups": {
		Name:        "Domain migration groups",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH (n:Group)
WHERE n.name CONTAINS "$$$@"
RETURN n
`,
	},
	"domains-affected-by-adprep-privilege-escalation-risk": {
		Name:        "Domains affected by AdPrep privilege escalation risk",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Group)-[r:GenericAll]->(m:Domain)
WHERE n.objectid ENDS WITH "-527" // Enterprise Key Admins
AND NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
`,
	},
	"domains-affected-by-exchange-privilege-escalation-risk": {
		Name:        "Domains affected by Exchange privilege escalation risk",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Group)-[r:WriteDacl|ForceChangePassword|AddMember]->(m:Base)
WHERE n.name STARTS WITH "EXCHANGE "
AND ((m:Tag_Tier_Zero) OR COALESCE(m.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
`,
	},
	"domains-allowing-authenticated-domain-enumeration": {
		Name:        "Domains allowing authenticated domain enumeration",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Group)-[:MemberOf]->(m:Group)
WHERE n.objectid ENDS WITH "S-1-5-11" // Authenticated Users
AND m.objectid ENDS WITH "S-1-5-32-554" // Pre-Windows 2000 Compatible Access
RETURN p
`,
	},
	"domains-allowing-unauthenticated-domain-enumeration": {
		Name:        "Domains allowing unauthenticated domain enumeration",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Group)-[:MemberOf]->(m:Group)
WHERE (n.objectid ENDS WITH "S-1-5-7" // Anonymous
OR n.objectid ENDS WITH "S-1-1-0") // Everyone
AND m.objectid ENDS WITH "S-1-5-32-554" // Pre-Windows 2000 Compatible Access
RETURN p
`,
	},
	"domains-allowing-unauthenticated-nspi-rpc-binds": {
		Name:        "Domains allowing unauthenticated NSPI RPC binds",
		Description: "Checks the fAllowAnonNSPI flag of dSHeuristics.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Domain)
WHERE n.dsheuristics =~ ".{7}[^0].*"
RETURN n
`,
	},
	"domains-allowing-unauthenticated-rootdse-searches-and-binds": {
		Name:        "Domains allowing unauthenticated rootDSE searches and binds",
		Description: "Checks the fLDAPBlockAnonOps flag of dSHeuristics.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Domain)
WHERE n.dsheuristics =~ ".{6}[^2].*"
RETURN n
`,
	},
	"domains-exempting-privileged-groups-from-adminsdholder-protections": {
		Name:        "Domains exempting privileged groups from AdminSDHolder protections",
		Description: "Checks the dwAdminSDExMask flag of dSHeuristics.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Domain)
WHERE n.dsheuristics =~ ".{15}[^0].*"
RETURN n
`,
	},
	"domains-not-mitigating-cve-2021-42291": {
		Name:        "Domains not mitigating CVE-2021-42291",
		Description: "Checks the AttributeAuthorizationOnLDAPAdd flag of dSHeuristics.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Domain)
WHERE n.dsheuristics =~ "^(.{0,27}|.{27}[^1].*)$"
RETURN n
`,
	},
	"domains-not-verifying-upn-and-spn-uniqueness": {
		Name:        "Domains not verifying UPN and SPN uniqueness",
		Description: "Checks the DoNotVerifyUPNAndOrSPNUniqueness flag of dSHeuristics.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Domain)
WHERE n.dsheuristics =~ ".{20}[^0].*"
RETURN n
`,
	},
	"domains-where-any-user-can-join-a-computer-to-the-domain": {
		Name:        "Domains where any user can join a computer to the domain",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (d:Domain)
WHERE d.machineaccountquota > 0
RETURN d
`,
	},
	"domains-with-a-minimum-default-password-policy-length-less-than-15-characters": {
		Name:        "Domains with a minimum default password policy length less than 15 characters",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Domain)
WHERE n.minpwdlength < 15
RETURN n
`,
	},
	"domains-with-a-single-point-of-failure-domain-controller": {
		Name:        "Domains with a single-point-of-failure Domain Controller",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Group)<-[:MemberOf]-(:Computer)
WHERE n.objectid ENDS WITH '-516'
WITH n, COUNT(n) AS dcCount
WHERE dcCount = 1
RETURN n
`,
	},
	"domains-with-functional-level-not-the-latest-version": {
		Name:        "Domains with functional level not the latest version",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Domain)
WHERE toString(n.functionallevel) IN ['2008','2003','2003 Interim','2000 Mixed/Native']
RETURN  n
`,
	},
	"domains-with-list-object-mode-enabled": {
		Name:        "Domains with List Object mode enabled",
		Description: "Checks the fDoListObject flag of dSHeuristics.",
		Category:    "Domain Information",
		Cypher: `
MATCH (n:Domain)
WHERE n.dsheuristics =~ ".{2}[^0].*"
RETURN n
`,
	},
	"domains-with-more-than-50-tier-zero-accounts": {
		Name:        "Domains with more than 50 Tier Zero accounts",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (d:Domain)-[:Contains*1..]->(n:Base)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
WITH d, COUNT(n) AS adminCount
WHERE adminCount > 50
RETURN d
`,
	},
	"domains-with-smart-card-accounts-where-smart-account-passwords-do-not-expire": {
		Name:        "Domains with smart card accounts where smart account passwords do not expire",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (s:Domain)-[:Contains*1..]->(t:Base)
WHERE s.expirepasswordsonsmartcardonlyaccounts = false
AND t.enabled = true
AND t.smartcardrequired = true
RETURN s
`,
	},
	"domains-without-microsoft-laps-computers": {
		Name:        "Domains without Microsoft LAPS computers",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH (d:Domain)
OPTIONAL MATCH (c:Computer)
WHERE c.domainsid = d.objectid AND c.haslaps = true
WITH d, COLLECT(c) AS computers
WHERE SIZE(computers) = 0
RETURN d
`,
	},
	"domains-without-protected-users-group": {
		Name:        "Domains without Protected Users group",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH (n:Domain)
WHERE n.collected = true
OPTIONAL MATCH (m:Group)
WHERE m.name ENDS WITH n.name
AND m.objectid ENDS WITH '-525'
WITH n, m
WHERE m IS NULL
RETURN n
`,
	},
	"enabled-built-in-guest-user-accounts": {
		Name:        "Enabled built-in guest user accounts",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:User)
WHERE n.objectid ENDS WITH "-501"
AND n.enabled = true
RETURN n
`,
	},
	"enabled-computers-inactive-for-180-days": {
		Name:        "Enabled computers inactive for 180 days",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
WITH 180 as inactive_days
MATCH (n:Computer)
WHERE n.enabled = true
AND n.lastlogontimestamp < (datetime().epochseconds - (inactive_days * 86400)) // Replicated value
AND n.lastlogon < (datetime().epochseconds - (inactive_days * 86400)) // Non-replicated value
AND n.whencreated < (datetime().epochseconds - (inactive_days * 86400)) // Exclude recently created principals
AND NOT n.name STARTS WITH 'AZUREADKERBEROS.' // Removes false positive, Azure KRBTGT
AND NOT n.name STARTS WITH 'AZUREADSSOACC.' // Removes false positive, Entra Seamless SSO
RETURN n
LIMIT 1000
`,
	},
	"enabled-computers-inactive-for-180-days---mssql-failover-cluster": {
		Name:        "Enabled computers inactive for 180 days - MSSQL Failover Cluster",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
WITH 180 as inactive_days
MATCH (n:Computer)
WHERE n.enabled = true
AND n.lastlogontimestamp < (datetime().epochseconds - (inactive_days * 86400)) // Replicated value
AND n.lastlogon < (datetime().epochseconds - (inactive_days * 86400)) // Non-replicated value
AND n.whencreated < (datetime().epochseconds - (inactive_days * 86400)) // Exclude recently created principals
AND ANY(type IN n.serviceprincipalnames WHERE 
    toLower(type) CONTAINS 'mssqlservercluster' OR 
    toLower(type) CONTAINS 'mssqlserverclustermgmtapi' OR 
    toLower(type) CONTAINS 'msclustervirtualserver')
RETURN n
LIMIT 1000
`,
	},
	"enabled-tier-zero-/-high-value-principals-inactive-for-60-days": {
		Name:        "Enabled Tier Zero / High Value principals inactive for 60 days",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
WITH 60 as inactive_days
MATCH (n:Base)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND n.enabled = true
AND n.lastlogontimestamp < (datetime().epochseconds - (inactive_days * 86400)) // Replicated value
AND n.lastlogon < (datetime().epochseconds - (inactive_days * 86400)) // Non-replicated value
AND n.whencreated < (datetime().epochseconds - (inactive_days * 86400)) // Exclude recently created principals
AND NOT n.name STARTS WITH 'AZUREADKERBEROS.' // Removes false positive, Azure KRBTGT
AND NOT n.objectid ENDS WITH '-500' // Removes false positive, built-in Administrator
AND NOT n.name STARTS WITH 'AZUREADSSOACC.' // Removes false positive, Entra Seamless SSO
RETURN n
`,
	},
	"enabled-users-inactive-for-180-days": {
		Name:        "Enabled users inactive for 180 days",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
WITH 180 as inactive_days
MATCH (n:User)
WHERE n.enabled = true
AND n.lastlogontimestamp < (datetime().epochseconds - (inactive_days * 86400)) // Replicated value
AND n.lastlogon < (datetime().epochseconds - (inactive_days * 86400)) // Non-replicated value
AND n.whencreated < (datetime().epochseconds - (inactive_days * 86400)) // Exclude recently created principals
AND NOT n.objectid ENDS WITH '-500' // Removes false positive, built-in Administrator
RETURN n
LIMIT 1000
`,
	},
	"enrollment-rights-on-certificate-templates-published-to-enterprise-ca-with-user-specified-san-enabled": {
		Name:        "Enrollment rights on certificate templates published to Enterprise CA with User Specified SAN enabled",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(eca:EnterpriseCA)
WHERE eca.isuserspecifiessanenabled = True
RETURN p
LIMIT 1000
`,
	},
	"enrollment-rights-on-certificate-templates-published-to-enterprise-ca-with-user-specified-san-enabled-esc6": {
		Name:        "Enrollment rights on certificate templates published to Enterprise CA with User Specified SAN enabled (ESC6)",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(eca:EnterpriseCA)
WHERE eca.isuserspecifiessanenabled = True
RETURN p
LIMIT 1000
`,
	},
	"enrollment-rights-on-certificate-templates-published-to-enterprise-ca-with-vulnerable-https-endpoint-esc8": {
		Name:        "Enrollment rights on certificate templates published to Enterprise CA with vulnerable HTTP(S) endpoint (ESC8)",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(eca:EnterpriseCA)
WHERE eca.hasvulnerableendpoint = True
RETURN p
LIMIT 1000
`,
	},
	"enrollment-rights-on-certtemplates-with-oidgrouplink": {
		Name:        "Enrollment rights on CertTemplates with OIDGroupLink",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(:CertTemplate)-[:ExtendedByPolicy]->(:IssuancePolicy)-[:OIDGroupLink]->(:Group)
RETURN p
LIMIT 1000
`,
	},
	"enrollment-rights-on-published-certificate-templates": {
		Name:        "Enrollment rights on published certificate templates",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
RETURN p
LIMIT 1000
`,
	},
	"enrollment-rights-on-published-certificate-templates-with-no-security-extension": {
		Name:        "Enrollment rights on published certificate templates with no security extension",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE ct.nosecurityextension = true
RETURN p
LIMIT 1000
`,
	},
	"enrollment-rights-on-published-enrollment-agent-certificate-templates": {
		Name:        "Enrollment rights on published enrollment agent certificate templates",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE '1.3.6.1.4.1.311.20.2.1' IN ct.effectiveekus
OR '2.5.29.37.0' IN ct.effectiveekus
OR SIZE(ct.effectiveekus) = 0
RETURN p
LIMIT 1000
`,
	},
	"enrollment-rights-on-published-esc1-certificate-templates": {
		Name:        "Enrollment rights on published ESC1 certificate templates",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE ct.enrolleesuppliessubject = True
AND ct.authenticationenabled = True
AND ct.requiresmanagerapproval = False
AND (ct.authorizedsignatures = 0 OR ct.schemaversion = 1)
RETURN p
LIMIT 1000
`,
	},
	"enrollment-rights-on-published-esc15-certificate-templates": {
		Name:        "Enrollment rights on published ESC15 certificate templates",
		Description: "Enrollment rights on certificate templates that meet the requirements for the ADCS ESC15 (EKUwu) attack.",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p=(:Base)-[:Enroll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)-[:TrustedForNTAuth]->(:NTAuthStore)-[:NTAuthStoreFor]->(:Domain)
WHERE ct.enrolleesuppliessubject = True
AND ct.authenticationenabled = False
AND ct.requiresmanagerapproval = False
AND ct.schemaversion = 1
RETURN p
`,
	},
	"enrollment-rights-on-published-esc2-certificate-templates": {
		Name:        "Enrollment rights on published ESC2 certificate templates",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(c:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE c.requiresmanagerapproval = false
AND (c.effectiveekus = [''] OR '2.5.29.37.0' IN c.effectiveekus OR c.effectiveekus IS NULL)
AND (c.authorizedsignatures = 0 OR c.schemaversion = 1)
RETURN p
LIMIT 1000
`,
	},
	"entra-id-sso-accounts-not-rolling-kerberos-decryption-key": {
		Name:        "Entra ID SSO accounts not rolling Kerberos decryption key",
		Description: "Microsoft highly recommends that you roll over the Entra ID SSO Kerberos decryption key at least every 30 days.",
		Category:    "Configuration Weakness",
		Cypher: `
MATCH (n:Computer)
WHERE n.name STARTS WITH "AZUREADSSOACC."
AND n.pwdlastset < (datetime().epochseconds - (30 * 86400))
RETURN n
`,
	},
	"entra-users-synced-from-on-prem-users-added-to-domain-admins-group": {
		Name:        "Entra Users synced from On-Prem Users added to Domain Admins group",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:AZUser)-[:SyncedToADUser]->(:User)-[:MemberOf]->(t:Group)
WHERE t.objectid ENDS WITH '-512'
RETURN p
LIMIT 1000
`,
	},
	"entra-users-with-entra-admin-role-approval-direct": {
		Name:        "Entra Users with Entra Admin Role approval (direct)",
		Description: "",
		Category:    "General",
		Cypher: `
MATCH p = (:AZUser)-[:AZRoleApprover]->(:AZRole)
RETURN p LIMIT 100
`,
	},
	"entra-users-with-entra-admin-role-approval-group-delegated": {
		Name:        "Entra Users with Entra Admin Role approval (group delegated)",
		Description: "",
		Category:    "General",
		Cypher: `
MATCH p = (:AZUser)-[:AZMemberOf]->(:AZGroup)-[:AZRoleApprover]->(:AZRole)
RETURN p LIMIT 100
`,
	},
	"entra-users-with-entra-admin-role-direct-eligibility": {
		Name:        "Entra Users with Entra Admin Role direct eligibility",
		Description: "",
		Category:    "General",
		Cypher: `
MATCH p = (:AZUser)-[:AZRoleEligible]->(:AZRole)
RETURN p LIMIT 100
`,
	},
	"entra-users-with-entra-admin-roles-group-delegated-eligibility": {
		Name:        "Entra Users with Entra Admin Roles group delegated eligibility",
		Description: "",
		Category:    "General",
		Cypher: `
MATCH p = (:AZUser)-[:AZMemberOf]->(:AZGroup)-[:AZRoleEligible]->(:AZRole)
RETURN p LIMIT 100
`,
	},
	"esc8-vulnerable-enterprise-cas": {
		Name:        "ESC8-vulnerable Enterprise CAs",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH (n:EnterpriseCA)
WHERE n.hasvulnerableendpoint=true
RETURN n
`,
	},
	"foreign-principals-in-tier-zero-/-high-value-targets": {
		Name:        "Foreign principals in Tier Zero / High Value targets",
		Description: "",
		Category:    "Azure Hygiene",
		Cypher: `
MATCH (n:AZServicePrincipal)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND NOT toUpper(n.appownerorganizationid) = toUpper(n.tenantid)
AND n.appownerorganizationid CONTAINS '-'
RETURN n
LIMIT 100
`,
	},
	"foreign-service-principals-with-an-entraid-admin-role": {
		Name:        "Foreign Service Principals With an EntraID Admin Role",
		Description: "Entra ID admin roles grant significant control over a tenant environment, even if the role is not a default Tier Zero / High Value role",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p = (sp:AZServicePrincipal)-[:AZHasRole]->(r:AZRole)
WHERE toUpper(sp.appownerorganizationid) <> toUpper(sp.tenantid)
// Ensure AZServicePrincipal has a valid appownerorganizationid
AND sp.appownerorganizationid CONTAINS "-"
RETURN p
LIMIT 1000
`,
	},
	"foreign-service-principals-with-any-abusable-ms-graph-app-role-assignment": {
		Name:        "Foreign Service Principals With any Abusable MS Graph App Role Assignment",
		Description: "MS Graph app role assignments provide significant power within an Entra ID tenant, similar to an Admin role.",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p = (sp1:AZServicePrincipal)-[r:AZMGGroupMember_ReadWrite_All|AZMGServicePrincipalEndpoint_ReadWrite_All|AZMGAppRoleAssignment_ReadWrite_All|AZMGGroup_ReadWrite_All|AZMGDirectory_ReadWrite_All|AZMGRoleManagement_ReadWrite_Directory]->(sp2:AZServicePrincipal)
WHERE toUpper(sp1.appownerorganizationid) <> toUpper(sp1.tenantid)
// Ensure AZServicePrincipal has a valid appownerorganizationid
AND sp1.appownerorganizationid CONTAINS "-"
RETURN p
LIMIT 1000
`,
	},
	"foreign-service-principals-with-group-memberships": {
		Name:        "Foreign Service Principals With Group Memberships",
		Description: "Review each to validate whether their presence is expected and whether the assigned group memberships are appropriate for the foreign service principal.",
		Category:    "Azure Hygiene",
		Cypher: `
MATCH p = (sp:AZServicePrincipal)-[:AZMemberOf]->(g:AZGroup)
WHERE toUpper(sp.appownerorganizationid) <> toUpper(g.tenantid)
// Ensure AZServicePrincipal has a valid appownerorganizationid
AND sp.appownerorganizationid CONTAINS "-"
RETURN p
LIMIT 1000
`,
	},
	"kerberoastable-members-of-tier-zero-/-high-value-groups": {
		Name:        "Kerberoastable members of Tier Zero / High Value groups",
		Description: "",
		Category:    "Kerberos Interaction",
		Cypher: `
MATCH (u:User)
WHERE ((u:Tag_Tier_Zero) OR COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0') AND u.hasspn=true
AND u.enabled = true
AND NOT u.objectid ENDS WITH '-502'
AND NOT COALESCE(u.gmsa, false) = true
AND NOT COALESCE(u.msa, false) = true 
RETURN u
LIMIT 100
`,
	},
	"kerberoastable-users-with-most-admin-privileges": {
		Name:        "Kerberoastable users with most admin privileges",
		Description: "",
		Category:    "Kerberos Interaction",
		Cypher: `
MATCH (u:User)
WHERE u.hasspn = true
  AND u.enabled = true
  AND NOT u.objectid ENDS WITH '-502'
  AND NOT COALESCE(u.gmsa, false) = true
  AND NOT COALESCE(u.msa, false) = true
MATCH (u)-[:MemberOf|AdminTo*1..]->(c:Computer)
WITH DISTINCT u, COUNT(c) AS adminCount
RETURN u
ORDER BY adminCount DESC
LIMIT 100
`,
	},
	"kerberos-enabled-service-account-member-of-built-in-admins-groups": {
		Name:        "Kerberos-enabled service account member of built-in Admins groups",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Base)-[:MemberOf*1..]->(g:Group)
WHERE (
  g.objectid ENDS WITH '-512' // Domain Admins
  OR g.objectid ENDS WITH '-519' // Enterprise Admins
  OR g.objectid ENDS WITH '-518' // Schema Admins
)
AND n.hasspn = true
RETURN p
`,
	},
	"kerberos-enabled-service-accounts-without-aes-encryption-support": {
		Name:        "Kerberos-enabled service accounts without AES encryption support",
		Description: "Accounts without Kerberos AES encryption support, or passwords set before the existence of Windows Server 2008 Domain Controller which therefore lack AES encryption keys.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE n.hasspn = true
AND ((
  n.supportedencryptiontypes <> ['Not defined']
  OR n.supportedencryptiontypes <> []
  OR NONE(type IN n.supportedencryptiontypes WHERE type CONTAINS 'AES128' OR type CONTAINS 'AES256')
)
OR (n.pwdlastset < 1204070400 // Password Last Set before Windows Server 2008
AND NOT n.pwdlastset IN [-1.0, 0.0]
))
RETURN n
LIMIT 100
`,
	},
	"krbtgt-accounts-with-passwords-not-rotated-in-over-1-year": {
		Name:        "KRBTGT accounts with passwords not rotated in over 1 year",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:User)
WHERE (n.objectid ENDS WITH '-502'
OR n.name STARTS WITH 'AZUREADKERBEROS.'
OR n.name STARTS WITH 'KRBTGT_AZUREAD@')
AND n.pwdlastset < (datetime().epochseconds - (365 * 86400))
RETURN n
`,
	},
	"large-default-group-added-to-computer-local-group": {
		Name:        "Large default group added to computer-local group",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Group)-[:MemberOfLocalGroup]->(m:ADLocalGroup)-[:LocalToComputer]->(:Computer)
WHERE n.objectid =~ ".*-(S-1-5-11|S-1-1-0|S-1-5-32-545|S-1-5-7|-513|-515)$" // Authenticated Users, Everyone, Users, Anonymous, Domain Users, Domain Computers
AND NOT m.objectid =~ ".*-(545|574|554)$" // Users, Certificate Service DCOM Access, Pre-Windows 2000 Compatible Access
RETURN p
`,
	},
	"large-default-groups-with-outbound-control": {
		Name:        "Large default groups with outbound control",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Group)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|AllowedToDelegate|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->(:Base)
WHERE n.objectid ENDS WITH "-513" // DOMAIN USERS
OR n.objectid ENDS WITH "-515" // DOMAIN COMPUTERS
OR n.objectid ENDS WITH "-S-1-5-11" // AUTHENTICATED USERS
OR n.objectid ENDS WITH "-S-1-1-0" // EVERYONE
OR n.objectid ENDS WITH "S-1-5-32-545" // USERS
OR n.objectid ENDS WITH "S-1-5-32-546" // GUESTS
OR n.objectid ENDS WITH "S-1-5-7" // ANONYMOUS
RETURN p
`,
	},
	"large-default-groups-with-outbound-control-of-ous": {
		Name:        "Large default groups with outbound control of OUs",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Group)-[]->(:OU)
WHERE n.objectid ENDS WITH "-513" // DOMAIN USERS
OR n.objectid ENDS WITH "-515" // DOMAIN COMPUTERS
OR n.objectid ENDS WITH "-S-1-5-11" // AUTHENTICATED USERS
OR n.objectid ENDS WITH "-S-1-1-0" // EVERYONE
OR n.objectid ENDS WITH "S-1-5-32-545" // USERS
OR n.objectid ENDS WITH "S-1-5-32-546" // GUESTS
OR n.objectid ENDS WITH "S-1-5-7" // ANONYMOUS
RETURN p
`,
	},
	"location-of-adminsdholder-protected-objects": {
		Name:        "Location of AdminSDHolder Protected objects",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p = (n:Base)<-[:Contains*1..]-(:Domain)
WHERE n.adminsdholderprotected = True
RETURN p
LIMIT 1000
`,
	},
	"locations-of-owned-objects": {
		Name:        "Locations of Owned objects",
		Description: "",
		Category:    "General",
		Cypher: `
MATCH p = (t:AZBase)<-[:AZContains*1..]-(:AZTenant)
WHERE ((t:Tag_Owned) OR COALESCE(t.system_tags, '') CONTAINS 'owned')
RETURN p
LIMIT 1000
`,
	},
	"locations-of-tier-zero-/-high-value-objects": {
		Name:        "Locations of Tier Zero / High Value objects",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p = (t:Base)<-[:Contains*1..]-(:Domain)
WHERE ((t:Tag_Tier_Zero) OR COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
LIMIT 1000
`,
	},
	"map-azure-management-structure": {
		Name:        "Map Azure Management structure",
		Description: "Maps the structure of Azure Management",
		Category:    "General",
		Cypher: `
MATCH p = (:AZTenant)-[:AZContains*1..]->(:AZResourceGroup)
RETURN p
LIMIT 1000
`,
	},
	"map-domain-trusts": {
		Name:        "Map domain trusts",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p = (:Domain)-[:SameForestTrust|CrossForestTrust]->(:Domain)
RETURN p
LIMIT 1000
`,
	},
	"map-ou-structure": {
		Name:        "Map OU structure",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p = (:Domain)-[:Contains*1..]->(:OU)
RETURN p
LIMIT 1000
`,
	},
	"members-of-allowed-rodc-password-replication-group": {
		Name:        "Members of Allowed RODC Password Replication Group",
		Description: "",
		Category:    "Domain Information",
		Cypher: `
MATCH p=(:Base)-[:MemberOf*1..]->(m:Group)
WHERE m.objectid ENDS WITH "-571"
RETURN p
`,
	},
	"microsoft-entra-connect-accounts-with-passwords-not-rotated-in-over-90-days": {
		Name:        "Microsoft Entra Connect accounts with passwords not rotated in over 90 days",
		Description: "Micosoft recommends to change the password of MSOL accounts every 90 days to prevent attackers from allowing use of the high privileges",
		Category:    "Active Directory Hygiene",
		Cypher: `
WITH 90 as days_since_change
MATCH (u:User)
WHERE u.name STARTS WITH "MSOL_"
AND u.pwdlastset < (datetime().epochseconds - (days_since_change * 86400))
AND NOT u.pwdlastset IN [-1.0, 0.0]
RETURN u
`,
	},
	"nested-groups-within-tier-zero-/-high-value": {
		Name:        "Nested groups within Tier Zero / High Value",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(t:Group)<-[:MemberOf*..]-(s:Group)
WHERE ((t:Tag_Tier_Zero) OR COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0')
AND NOT s.objectid ENDS WITH '-512' // Domain Admins
AND NOT s.objectid ENDS WITH '-519' // Enterprise Admins
RETURN p
LIMIT 1000
`,
	},
	"non-default-delegation-on-microsoftdns-container": {
		Name:        "Non-default delegation on MicrosoftDNS container",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Base)-[r]->(m:Container)
WHERE m.distinguishedname STARTS WITH "CN=MICROSOFTDNS,CN=SYSTEM,DC="
AND NOT n.name STARTS WITH "DNSADMINS@"
AND NOT n.objectid =~ "-(512|544|519|9)$"
AND r.isacl
RETURN p
`,
	},
	"non-default-members-in-pre-windows-2000-compatible-access": {
		Name:        "Non-default members in Pre-Windows 2000 Compatible Access",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Group)-[:MemberOf]->(m:Group)
WHERE NOT n.objectid ENDS WITH "S-1-5-11" // Authenticated Users
AND NOT (n.objectid ENDS WITH "S-1-5-7" // Anonymous
AND NOT n.objectid ENDS WITH "S-1-1-0") // Everyone
AND m.objectid ENDS WITH "S-1-5-32-554" // Pre-Windows 2000 Compatible Access
RETURN p
`,
	},
	"non-default-permissions-on-issuancepolicy-nodes": {
		Name:        "Non-default permissions on IssuancePolicy nodes",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (s:Base)-[:GenericAll|GenericWrite|Owns|WriteOwner|WriteDacl]->(:IssuancePolicy)
WHERE NOT s.objectid ENDS WITH '-512' AND NOT s.objectid ENDS WITH '-519'
RETURN p
LIMIT 1000
`,
	},
	"non-tier-zero-account-with-'admin-count'-flag": {
		Name:        "Non-Tier Zero account with 'Admin Count' flag",
		Description: "Accounts that were members of AD's built-in administrative groups, thus had the 'AdminCount' flag set, but are not currently in those groups and not tagged as Tier Zero. These accounts could still be highly privileged by other means.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE (n:User OR n:Computer)
AND n.admincount = true
AND NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND NOT n.objectid ENDS WITH '-502' // KRBTGT user
AND NOT n.objectid ENDS WITH '-500' // Administrator user
OPTIONAL MATCH (n)-[:MemberOf]->(g:Group)
WHERE g.objectid ENDS WITH '-512' // Domain Admins
OR g.objectid ENDS WITH '-548' // Account Operators
OR g.objectid ENDS WITH '-544' // Administrators
OR g.objectid ENDS WITH '-551' // Backup Operators
OR g.objectid ENDS WITH '-516' // Domain Controllers
OR g.objectid ENDS WITH '-519' // Enterprise Admins
OR g.objectid ENDS WITH '-527' // Enterprise Key Admins
OR g.objectid ENDS WITH '-526' // Key Admins
OR g.objectid ENDS WITH '-550' // Print Operators
OR g.objectid ENDS WITH '-521' // Read-Only Domain Controllers
OR g.objectid ENDS WITH '-552' // Replicators
OR g.objectid ENDS WITH '-518' // Schema Admins
OR g.objectid ENDS WITH '-549' // Server Operators
WITH n, g
WHERE g IS NULL
RETURN n
`,
	},
	"non-tier-zero-account-with-unconstrained-delegation": {
		Name:        "Non-Tier Zero account with unconstrained delegation",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH (n:Base)
WHERE n.unconstraineddelegation = true
AND NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN n
`,
	},
	"non-tier-zero-accounts-with-sid-history-of-tier-zero-accounts": {
		Name:        "Non-Tier Zero accounts with SID History of Tier Zero accounts",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Base)-[:HasSIDHistory]->(m:Base)
WHERE ((m:Tag_Tier_Zero) OR COALESCE(m.system_tags, '') CONTAINS 'admin_tier_0')
AND NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
`,
	},
	"non-tier-zero-object-with-excessive-control": {
		Name:        "Non-Tier Zero object with excessive control",
		Description: "Returns non-Tier Zero principals with >= 1000 direct rights to other principals. This does not include rights from group memberships.",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH (n:Base)-[r:AD_ATTACK_PATHS]->(m:Base)
WHERE NOT r:MemberOf
AND NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
WITH n, COLLECT(DISTINCT(m)) AS endNodes
WHERE SIZE(endNodes) >= 1000
RETURN n
`,
	},
	"non-tier-zero-principals-with-badsuccessor-rights-no-prerequisites-check": {
		Name:        "Non-Tier Zero principals with BadSuccessor rights (no prerequisites check)",
		Description: "Finds non-Tier Zero principals with BadSuccessor rights with no prerequisites check (DC2025 & KDC key).",
		Category:    "Dangerous Privileges",
		Cypher: `
// Find OU control
MATCH p = (ou:OU)<-[:WriteDacl|Owns|GenericAll|WriteOwner]-(n:Base)
// Exclude Tier Zero
WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p LIMIT 1000
`,
	},
	"non-tier-zero-principals-with-badsuccessor-rights-with-prerequisites-check": {
		Name:        "Non-Tier Zero principals with BadSuccessor rights (with prerequisites check)",
		Description: "Finds non-Tier Zero principals with BadSuccessor rights after checking prerequisites check (DC2025 & KDC key).",
		Category:    "Dangerous Privileges",
		Cypher: `
// Find 2025 DCs
MATCH (dc:Computer)
WHERE dc.isdc = true AND dc.operatingsystem CONTAINS '2025'
// Find gMSAs
MATCH (m:User)
WHERE m.gmsa = true
// Find OU control
MATCH p = (ou:OU)<-[:WriteDacl|Owns|GenericAll|WriteOwner]-(n:Base)
// Confirm domain has a 2025 DC
WHERE ou.domain = dc.domain
// Confirm domain KDC key
AND ou.domain = m.domain
// Exclude Tier Zero
AND NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p LIMIT 1000
`,
	},
	"non-tier-zero-principals-with-control-of-adminsdholder": {
		Name:        "Non-Tier Zero principals with control of AdminSDHolder",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Group)-[r:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteOwnerLimitedRights|OwnsLimitedRights]->(m:Container)
WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND m.name STARTS WITH "ADMINSDHOLDER@"
RETURN p
`,
	},
	"object-name-conflict": {
		Name:        "Object name conflict",
		Description: "When two objects are created with the same Relative Distinguished Name (RDN) in the same parent Organizational Unit or container, the conflict is recognized by the system when one of the new objects replicates to another domain controller. When this happens, one of the objects is renamed with 'CNF'",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE n.distinguishedname CONTAINS 'CNF:'
RETURN n
`,
	},
	"on-prem-users-synced-to-entra-users-that-own-entra-objects": {
		Name:        "On-Prem Users synced to Entra Users that Own Entra Objects",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZOwns]->(:AZBase)
RETURN p
LIMIT 1000
`,
	},
	"on-prem-users-synced-to-entra-users-with-azure-rm-roles-direct": {
		Name:        "On-Prem Users synced to Entra Users with Azure RM Roles (direct)",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZOwner|AZUserAccessAdministrator|AZGetCertificates|AZGetKeys|AZGetSecrets|AZAvereContributor|AZKeyVaultContributor|AZContributor|AZVMAdminLogin|AZVMContributor|AZAKSContributor|AZAutomationContributor|AZLogicAppContributor|AZWebsiteContributor]->(:AZBase)
RETURN p
LIMIT 1000
`,
	},
	"on-prem-users-synced-to-entra-users-with-azure-rm-roles-group-delegated": {
		Name:        "On-Prem Users synced to Entra Users with Azure RM Roles (group delegated)",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZMemberOf]->(:AZGroup)-[:AZOwner|AZUserAccessAdministrator|AZGetCertificates|AZGetKeys|AZGetSecrets|AZAvereContributor|AZKeyVaultContributor|AZContributor|AZVMAdminLogin|AZVMContributor|AZAKSContributor|AZAutomationContributor|AZLogicAppContributor|AZWebsiteContributor]->(:AZBase)
RETURN p
LIMIT 1000
`,
	},
	"on-prem-users-synced-to-entra-users-with-entra-admin-roles-direct": {
		Name:        "On-Prem Users synced to Entra Users with Entra Admin Roles (direct)",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZHasRole]->(:AZRole)
RETURN p
LIMIT 1000
`,
	},
	"on-prem-users-synced-to-entra-users-with-entra-admin-roles-group-delegated": {
		Name:        "On-Prem Users synced to Entra Users with Entra Admin Roles (group delegated)",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZMemberOf]->(:AZGroup)-[:AZHasRole]->(:AZRole)
RETURN p
LIMIT 1000
`,
	},
	"on-prem-users-synced-to-entra-users-with-entra-group-membership": {
		Name:        "On-Prem Users synced to Entra Users with Entra Group Membership",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZMemberOf]->(:AZGroup)
RETURN p
LIMIT 1000
`,
	},
	"overprivileged-microsoft-entra-connect-accounts": {
		Name:        "Overprivileged Microsoft Entra Connect accounts",
		Description: "Legacy MSOL accounts were by default deployed with Domain Admins or Enterprise Admins membership.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:User)-[:MemberOf*1..]->(g:Group)
WHERE n.name STARTS WITH "MSOL_"
AND (g.objectid ENDS WITH "-512" // Domain Admins
OR g.objectid ENDS WITH "-519") // Entterprise Admins
RETURN p
`,
	},
	"paths-from-domain-users-to-tier-zero-/-high-value-targets": {
		Name:        "Paths from Domain Users to Tier Zero / High Value targets",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=shortestPath((s:Group)-[:AD_ATTACK_PATHS*1..]->(t:Base))
WHERE s.objectid ENDS WITH '-513' AND s<>t
AND ((t:Tag_Tier_Zero) OR COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
LIMIT 1000
`,
	},
	"pki-hierarchy": {
		Name:        "PKI hierarchy",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p=()-[:HostsCAService|IssuedSignedBy|EnterpriseCAFor|RootCAFor|TrustedForNTAuth|NTAuthStoreFor*..]->(:Domain)
RETURN p
LIMIT 1000
`,
	},
	"potential-gpo-'apply'-misconfiguration": {
		Name:        "Potential GPO 'Apply' misconfiguration",
		Description: "In Active Directory, GPO's are applied to objects in the Group Policy Management Console by ticking \"Allow - Apply group policy\", but administrators can mistakenly tick \"Allow - Write\" or \"Allow - Full Control\" resulting in a misconfigured GPO that allows a principal to compromise other principals the GPO also applies to. Results are potential risks and must be audited for for correctness.",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Base)-[:GenericAll|GenericWrite]->(g:GPO)

// Exclude Enterprise Admins and Domain Admins
WHERE NOT n.objectid =~ "-(519|512)$"

// Exclude unresolved SIDs
AND NOT (n.distinguishedname IS NULL)

// Asset description may reveal if it's a delegation group (false-positive) or a filter group (true-positive)
//AND n.description is not null
//AND n.description =~ "(?i)apply"

RETURN p
LIMIT 1000
`,
	},
	"principal-with-spn-keyword": {
		Name:        "Principal with SPN keyword",
		Description: "Finds service accounts used with a specific Kerberos-enabled service or all service accounts running on a Kerberos-enabled service on a specific server.",
		Category:    "Kerberos Interaction",
		Cypher: `
// Replace keyword with a service type or server name (not FQDN)
WITH "KEYWORD" as SPNKeyword
MATCH (n:User)
WHERE ANY(keyword IN n.serviceprincipalnames WHERE toUpper(keyword) CONTAINS toUpper(SPNKeyword))
RETURN n
`,
	},
	"principals-with-dcsync-privileges": {
		Name:        "Principals with DCSync privileges",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(:Base)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain)
RETURN p
LIMIT 1000
`,
	},
	"principals-with-des-only-kerberos-authentication": {
		Name:        "Principals with DES-only Kerberos authentication",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE n.enabled = true
AND n.usedeskeyonly = true
RETURN n
`,
	},
	"principals-with-foreign-domain-group-membership": {
		Name:        "Principals with foreign domain group membership",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(s:Base)-[:MemberOf]->(t:Group)
WHERE s.domainsid<>t.domainsid
RETURN p
LIMIT 1000
`,
	},
	"principals-with-passwords-stored-using-reversible-encryption": {
		Name:        "Principals with passwords stored using reversible encryption",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE n.encryptedtextpwdallowed = true
RETURN n
`,
	},
	"principals-with-weak-supported-kerberos-encryption-types": {
		Name:        "Principals with weak supported Kerberos encryption types",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (u:Base)
WHERE 'DES-CBC-CRC' IN u.supportedencryptiontypes
OR 'DES-CBC-MD5' IN u.supportedencryptiontypes
OR 'RC4-HMAC-MD5' IN u.supportedencryptiontypes
RETURN u
`,
	},
	"public-key-services-container": {
		Name:        "Public Key Services container",
		Description: "",
		Category:    "Active Directory Certificate Services",
		Cypher: `
MATCH p = (c:Container)-[:Contains*..]->(:Base)
WHERE c.distinguishedname starts with 'CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC='
RETURN p
LIMIT 1000
`,
	},
	"servers-where-domain-users-can-rdp": {
		Name:        "Servers where Domain Users can RDP",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(s:Group)-[:CanRDP]->(t:Computer)
WHERE s.objectid ENDS WITH '-513' AND toUpper(t.operatingsystem) CONTAINS 'SERVER'
RETURN p
LIMIT 1000
`,
	},
	"sessions-across-trusts": {
		Name:        "Sessions across trusts",
		Description: "Users logging on across a trust, the users originate from trusted domains.",
		Category:    "Domain Information",
		Cypher: `
MATCH p=(trustedDomainPrincipal:Computer)-[r:HasSession]->(trustingDomainPrincipal:User)
WHERE trustedDomainPrincipal.domainsid <> trustingDomainPrincipal.domainsid
RETURN p
LIMIT 1000
`,
	},
	"shortest-path-owned-->-da": {
		Name:        "Shortest Path (Owned -> DA)",
		Description: "Finds shortest path from any user marked 'owned' to Domain Admins",
		Category:    "Custom",
		Cypher: `
MATCH (n:User {owned: true}), (m:Group {name: "DOMAIN ADMINS"})
MATCH p=shortestPath((n)-[*1..]->(m))
RETURN [node IN nodes(p) | {
    name: node.name,
    type: labels(node)[0]
}]
`,
	},
	"shortest-paths-from-azure-applications-to-tier-zero-/-high-value-targets": {
		Name:        "Shortest paths from Azure Applications to Tier Zero / High Value targets",
		Description: "WARNING! MANY-TO-MANY SHORTEST PATH QUERIES USE EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s:AZApp)-[:AZ_ATTACK_PATHS*1..]->(t:AZBase))
WHERE ((t:Tag_Tier_Zero) OR COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0') AND s<>t
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-from-domain-users-to-tier-zero-/-high-value-targets": {
		Name:        "Shortest paths from Domain Users to Tier Zero / High Value targets",
		Description: "",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s:Group)-[:AD_ATTACK_PATHS*1..]->(t:Base))
WHERE s.objectid ENDS WITH '-513' AND s<>t
AND ((t:Tag_Tier_Zero) OR COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-from-entra-users-to-tier-zero-/-high-value-targets": {
		Name:        "Shortest paths from Entra Users to Tier Zero / High Value targets",
		Description: "WARNING! MANY-TO-MANY SHORTEST PATH QUERIES USE EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s:AZUser)-[:AZ_ATTACK_PATHS*1..]->(t:AZBase))
WHERE ((t:Tag_Tier_Zero) OR COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-from-owned-objects": {
		Name:        "Shortest paths from Owned objects",
		Description: "",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s:Base)-[:AD_ATTACK_PATHS*1..]->(t:Base))
WHERE ((s:Tag_Owned) OR COALESCE(s.system_tags, '') CONTAINS 'owned')
AND s<>t
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-from-owned-objects-to-tier-zero": {
		Name:        "Shortest paths from Owned objects to Tier Zero",
		Description: "WARNING! MANY-TO-MANY SHORTEST PATH QUERIES USE EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE",
		Category:    "Shortest Paths",
		Cypher: `
// MANY TO MANY SHORTEST PATH QUERIES USE EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE
MATCH p=shortestPath((s:Tag_Owned)-[:AD_ATTACK_PATHS*1..]->(t:Base))
WHERE s<>t
AND ((t:Tag_Tier_Zero) OR COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-to-azure-subscriptions": {
		Name:        "Shortest paths to Azure Subscriptions",
		Description: "WARNING! MANY-TO-MANY SHORTEST PATH QUERIES USE EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s:AZBase)-[:AZ_ATTACK_PATHS*1..]->(t:AZSubscription))
WHERE s<>t
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-to-domain-admins": {
		Name:        "Shortest paths to Domain Admins",
		Description: "",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((t:Group)<-[:AD_ATTACK_PATHS*1..]-(s:Base))
WHERE t.objectid ENDS WITH '-512' AND s<>t
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-to-domain-admins-from-kerberoastable-users": {
		Name:        "Shortest paths to Domain Admins from Kerberoastable users",
		Description: "",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Group))
WHERE s.hasspn=true
AND s.enabled = true
AND NOT s.objectid ENDS WITH '-502'
AND NOT COALESCE(s.gmsa, false) = true
AND NOT COALESCE(s.msa, false) = true
AND t.objectid ENDS WITH '-512'
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-to-privileged-roles": {
		Name:        "Shortest paths to privileged roles",
		Description: "WARNING! MANY-TO-MANY SHORTEST PATH QUERIES USE EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s:AZBase)-[:AZ_ATTACK_PATHS*1..]->(t:AZRole))
WHERE t.name =~ '(?i)Global Administrator|User Administrator|Cloud Application Administrator|Authentication Policy Administrator|Exchange Administrator|Helpdesk Administrator|Privileged Authentication Administrator|Privileged Role Administrator' AND s<>t
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-to-systems-trusted-for-unconstrained-delegation": {
		Name:        "Shortest paths to systems trusted for unconstrained delegation",
		Description: "",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s)-[:AD_ATTACK_PATHS*1..]->(t:Computer))
WHERE t.unconstraineddelegation = true AND s<>t
RETURN p
LIMIT 1000
`,
	},
	"shortest-paths-to-tier-zero-/-high-value-targets": {
		Name:        "Shortest paths to Tier Zero / High Value targets",
		Description: "",
		Category:    "Shortest Paths",
		Cypher: `
MATCH p=shortestPath((s)-[:AD_ATTACK_PATHS*1..]->(t:Base))
WHERE ((t:Tag_Tier_Zero) OR (COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0'))
AND s<>t
RETURN p
LIMIT 1000
`,
	},
	"smart-card-accounts-with-passwords-not-rotated-in-over-1-year": {
		Name:        "Smart card accounts with passwords not rotated in over 1 year",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE n.pwdlastset < (datetime().epochseconds - (365 * 86400))
AND n.enabled = true
AND n.smartcardrequired = true
RETURN n
`,
	},
	"synced-entra-users-with-entra-admin-role-approval-direct": {
		Name:        "Synced Entra Users with Entra Admin Role approval (direct)",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZRoleApprover]->(:AZRole)
RETURN p LIMIT 100
`,
	},
	"synced-entra-users-with-entra-admin-role-approval-group-delegated": {
		Name:        "Synced Entra Users with Entra Admin Role approval (group delegated)",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZMemberOf]->(:AZGroup)-[:AZRoleApprover]->(:AZRole)
RETURN p LIMIT 100
`,
	},
	"synced-entra-users-with-entra-admin-role-direct-eligibility": {
		Name:        "Synced Entra Users with Entra Admin Role direct eligibility",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZRoleEligible]->(:AZRole)
RETURN p LIMIT 100
`,
	},
	"synced-entra-users-with-entra-admin-roles-group-delegated-eligibility": {
		Name:        "Synced Entra Users with Entra Admin Roles group delegated eligibility",
		Description: "",
		Category:    "Cross Platform Attack Paths",
		Cypher: `
MATCH p = (:User)-[:SyncedToEntraUser]->(:AZUser)-[:AZMemberOf]->(:AZGroup)-[:AZRoleEligible]->(:AZRole)
RETURN p LIMIT 100
`,
	},
	"tier-zero-/-high-value-enabled-users-not-requiring-smart-card-authentication": {
		Name:        "Tier Zero / High Value enabled users not requiring smart card authentication",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (u:User)
WHERE ((u:Tag_Tier_Zero) OR COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0')
AND u.enabled = true
AND u.smartcardrequired = false
AND NOT u.name STARTS WITH 'MSOL_' // Removes false positive, Entra sync
AND NOT u.name STARTS WITH 'PROVAGENTGMSA' // Removes false positive, Entra sync
AND NOT u.name STARTS WITH 'ADSYNCMSA_' // Removes false positive, Entra sync
RETURN u
`,
	},
	"tier-zero-/-high-value-external-entra-id-users": {
		Name:        "Tier Zero / High Value external Entra ID users",
		Description: "",
		Category:    "Azure Hygiene",
		Cypher: `
MATCH (n:AZUser)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND n.name CONTAINS '#EXT#@'
RETURN n
LIMIT 100
`,
	},
	"tier-zero-/-high-value-users-with-non-expiring-passwords": {
		Name:        "Tier Zero / High Value users with non-expiring passwords",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (u:User)
WHERE ((u:Tag_Tier_Zero) OR COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0') AND u.enabled = true
AND u.pwdneverexpires = true
RETURN u
LIMIT 100
`,
	},
	"tier-zero-accounts-not-members-of-denied-rodc-password-replication-group": {
		Name:        "Tier Zero accounts not members of Denied RODC Password Replication Group",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
// Get all Tier Zero accounts that are members of Denied RODC Password Replication Group
MATCH (n:Base)-[:MemberOf*1..]->(m:Group)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND (n:User OR n:Computer)
AND m.objectid ENDS WITH '-519'
WITH COLLECT(n.objectid) AS MembersOfDeniedGroup

// Get all Tier Zero accounts
MATCH (x:Base)
WHERE ((x:Tag_Tier_Zero) OR COALESCE(x.system_tags, '') CONTAINS 'admin_tier_0')
AND (x:User OR x:Computer)

// Filter the members of Denied RODC Password Replication Group
AND NOT x.objectid IN MembersOfDeniedGroup
RETURN x
`,
	},
	"tier-zero-accounts-that-can-be-delegated": {
		Name:        "Tier Zero accounts that can be delegated",
		Description: "",
		Category:    "Kerberos Interaction",
		Cypher: `
MATCH (m:Base)
WHERE ((m:Tag_Tier_Zero) OR COALESCE(m.system_tags, '') CONTAINS 'admin_tier_0')
AND m.enabled = true
AND m.sensitive = false
OPTIONAL MATCH (g:Group)<-[:MemberOf*1..]-(n:Base)
WHERE g.objectid ENDS WITH '-525'
WITH m, COLLECT(n) AS matchingNs
WHERE NONE(n IN matchingNs WHERE n.objectid = m.objectid)
RETURN m
`,
	},
	"tier-zero-ad-principals-synchronized-with-entra-id": {
		Name:        "Tier Zero AD principals synchronized with Entra ID",
		Description: "",
		Category:    "Azure Hygiene",
		Cypher: `
MATCH (ENTRA:AZBase)
MATCH (AD:Base)
WHERE ((AD:Tag_Tier_Zero) OR COALESCE(AD.system_tags, '') CONTAINS 'admin_tier_0')
AND ENTRA.onpremsyncenabled = true
AND ENTRA.onpremid = AD.objectid
RETURN ENTRA
// Replace 'RETURN ENTRA' with 'RETURN AD' to see the corresponding AD principals
LIMIT 100
`,
	},
	"tier-zero-computers-at-risk-of-constrained-delegation": {
		Name:        "Tier Zero computers at risk of constrained delegation",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p = (n:Computer)<-[:AllowedToDelegate]-(:Base)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
`,
	},
	"tier-zero-computers-at-risk-of-resource-based-constrained-delegation": {
		Name:        "Tier Zero computers at risk of resource-based constrained delegation",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p = (n:Computer)<-[:AllowedToAct]-(:Base)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
`,
	},
	"tier-zero-computers-not-owned-by-tier-zero": {
		Name:        "Tier Zero computers not owned by Tier Zero",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(n:Base)-[:Owns]->(:Computer)
WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
`,
	},
	"tier-zero-computers-not-requiring-inbound-smb-signing": {
		Name:        "Tier Zero computers not requiring inbound SMB signing",
		Description: "",
		Category:    "NTLM Relay Attacks",
		Cypher: `
MATCH (n:Computer)
WHERE n.smbsigning = False
AND ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN n
`,
	},
	"tier-zero-computers-with-passwords-older-than-the-default-maximum-password-age": {
		Name:        "Tier Zero computers with passwords older than the default maximum password age",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Computer)
WHERE n.enabled = true
AND n.whencreated < (datetime().epochseconds - (60 * 3 * 86400))
AND n.pwdlastset < (datetime().epochseconds - (60 * 3 * 86400))
AND ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN n
`,
	},
	"tier-zero-computers-with-the-webclient-running": {
		Name:        "Tier Zero computers with the WebClient running",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (c:Computer)
WHERE c.webclientrunning = True
AND ((c:Tag_Tier_Zero) OR COALESCE(c.system_tags, '') CONTAINS 'admin_tier_0')
RETURN c LIMIT 1000
`,
	},
	"tier-zero-computers-with-unsupported-operating-systems": {
		Name:        "Tier Zero computers with unsupported operating systems",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (c:Computer)
WHERE c.operatingsystem =~ '(?i).*Windows.* (2000|2003|2008|2012|xp|vista|7|8|me|nt).*'
AND ((c:Tag_Tier_Zero) OR COALESCE(c.system_tags, '') CONTAINS 'admin_tier_0')
RETURN c
LIMIT 100
`,
	},
	"tier-zero-principals-without-adminsdholder-protection": {
		Name:        "Tier Zero principals without AdminSDHolder protection",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:Base)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND n.adminsdholderprotected = false
RETURN n
LIMIT 500
`,
	},
	"tier-zero-users-not-member-of-protected-users": {
		Name:        "Tier Zero users not member of Protected Users",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (m:User)
WHERE ((m:Tag_Tier_Zero) OR COALESCE(m.system_tags, '') CONTAINS 'admin_tier_0')
OPTIONAL MATCH (g:Group)<-[:MemberOf*1..]-(n:Base)
WHERE g.objectid ENDS WITH '-525'
WITH m, COLLECT(n) AS matchingNs
WHERE NONE(n IN matchingNs WHERE n.objectid = m.objectid)
RETURN m
`,
	},
	"tier-zero-users-with-email": {
		Name:        "Tier Zero users with email",
		Description: "Tier Zero accounts with email access have an increased attack surface.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND n.email <> ""
AND n.enabled = true
AND NOT toUpper(n.email) ENDS WITH ".ONMICROSOFT.COM"
AND NOT (
    (toUpper(n.email) STARTS WITH "HEALTHMAILBOX"
    OR toUpper(n.email) STARTS WITH "MSEXCHDISCOVERYMAILBOX"
    OR toUpper(n.email) STARTS WITH "MSEXCHDISCOVERY"
    OR toUpper(n.email) STARTS WITH "MSEXCHAPPROVAL"
    OR toUpper(n.email) STARTS WITH "FEDERATEDEMAIL"
    OR toUpper(n.email) STARTS WITH "SYSTEMMAILBOX"
    OR toUpper(n.email) STARTS WITH "MIGRATION.")
  AND
    (n.name STARTS WITH "SM_"
    OR n.name STARTS WITH "HEALTHMAILBOX")
)
RETURN n
`,
	},
	"tier-zero-users-with-passwords-not-rotated-in-over-1-year": {
		Name:        "Tier Zero users with passwords not rotated in over 1 year",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
WITH 365 as days_since_change
MATCH (u:User)
WHERE ((u:Tag_Tier_Zero) OR COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0')
AND u.pwdlastset < (datetime().epochseconds - (days_since_change * 86400))
AND NOT u.pwdlastset IN [-1.0, 0.0]
RETURN u
LIMIT 100
`,
	},
	"uncommon-permission-on-containers": {
		Name:        "Uncommon permission on containers",
		Description: "BloodHound typically identifies risk on Active Directory objects stored in OUs, however behind the scenes; Active Directory has a hieracy of containers e.g. CN=SYSTEM and CN=CONFIGURATION, on which control can lead to risk. Results are prone to false-positives but can assist auditing containers permissions.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(:Domain)-[:Contains*1..]->(c:Container)<-[r]-(n:Base)

// Exclude Tier Zero
WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')

// Scope edges to ACLs
AND r.isacl

// Exclude CN=Users and CN=Computers containers
AND NOT c.distinguishedname STARTS WITH "CN=COMPUTERS,DC="
AND NOT c.distinguishedname STARTS WITH "CN=USERS,DC="

// Exclude same-domain unresolved SIDs
AND NOT (n.distinguishedname IS NULL AND n.domainsid = c.domainsid)

// Exclude default: Cert Publishers
AND NOT (c.distinguishedname CONTAINS ",CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=" AND n.objectid ENDS WITH "-517")

// Exclude default: RAS and IAS Servers
AND NOT (c.distinguishedname CONTAINS "CN=RAS AND IAS SERVERS ACCESS CHECK,CN=SYSTEM,DC=" AND n.objectid ENDS WITH "-553")

// Exclude default: DNS
AND NOT (c.distinguishedname CONTAINS "CN=MICROSOFTDNS,CN=SYSTEM,DC=" AND n.name STARTS WITH "DNSADMINS@")

// Exclude default: ConfigMgr
AND NOT (c.distinguishedname STARTS WITH "CN=SYSTEM MANAGEMENT,CN=SYSTEM,DC=" AND n.samaccountname ENDS WITH "$")

// Exclude default: Exchange pt1
AND NOT (c.distinguishedname CONTAINS "CN=MICROSOFT EXCHANGE,CN=SERVICES,CN=CONFIGURATION,DC=" AND (n.name STARTS WITH "EXCHANGE TRUSTED SUBSYSTEM@" OR n.name STARTS WITH "ORGANIZATION MANAGEMENT@" OR n.name STARTS WITH "EXCHANGE SERVICES@"))

// Exclude default: Exchange pt2
AND NOT ((c.distinguishedname CONTAINS "CN=MONITORING MAILBOXES,CN=MICROSOFT EXCHANGE SYSTEM OBJECTS,DC=" OR c.distinguishedname CONTAINS "CN=MICROSOFT EXCHANGE SYSTEM OBJECTS,DC=") AND n.name STARTS WITH "EXCHANGE ENTERPRISE SERVERS@")

// Exclude default: Exchange pt3
AND NOT ((c.distinguishedname CONTAINS "CN=ACTIVE DIRECTORY CONNECTIONS,CN=MICROSOFT EXCHANGE,CN=SERVICES,CN=CONFIGURATION,DC=" OR c.distinguishedname CONTAINS "CN=MICROSOFT EXCHANGE SYSTEM OBJECTS,DC=" OR c.distinguishedname =~ "CN=RECIPIENT UPDATE SERVICES,CN=ADDRESS LISTS CONTAINER,CN=.*,CN=MICROSOFT EXCHANGE,CN=SERVICES,CN=CONFIGURATION,DC=") AND n.name STARTS WITH "EXCHANGE DOMAIN SERVERS@")

RETURN p
LIMIT 2000
`,
	},
	"unresolved-sid-with-outbound-control": {
		Name:        "Unresolved SID with outbound control",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:Base)-[r]->(:Base)
WHERE r.isacl
AND n.name CONTAINS "S-1-5-21-" // Unresolved SID
RETURN p
LIMIT 1000
`,
	},
	"usage-of-built-in-domain-administrator-account": {
		Name:        "Usage of built-in domain Administrator account",
		Description: "Usage of Active Directory's built-in Administrator account is a sign that the account is not only used for break-glass purposes.",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:User)
WHERE n.objectid ENDS WITH "-500"
AND (
 n.lastlogontimestamp > (datetime().epochseconds - (60 * 86400)) OR
 n.lastlogon > (datetime().epochseconds - (60 * 86400))
)
AND NOT n.whencreated > (datetime().epochseconds - (60 * 86400))
RETURN n
`,
	},
	"users-which-do-not-require-password-to-authenticate": {
		Name:        "Users which do not require password to authenticate",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (u:User)
WHERE u.passwordnotreqd = true
RETURN u
LIMIT 100
`,
	},
	"users-with-logon-scripts-stored-in-a-trusted-domain": {
		Name:        "Users with logon scripts stored in a trusted domain",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (n:User)
WHERE n.logonscript IS NOT NULL
MATCH (d:Domain)<-[:SameForestTrust|CrossForestTrust]-(:Domain)-[:Contains*1..]->(n)
WITH n,last(split(d.name, '@')) AS domain
WHERE toUpper(n.logonscript) STARTS WITH ("\\\\" + domain + "\\")
RETURN n
`,
	},
	"users-with-non-default-primary-group-membership": {
		Name:        "Users with non-default Primary Group membership",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH p=(n:User)-[r:MemberOf]->(g:Group)
WHERE NOT g.objectid ENDS WITH "-513" // Domain Users
AND r.isprimarygroup = true
AND NOT n.objectid ENDS WITH "-501" // Guests account, as it has primaryGroup to Guests
AND (n.gmsa IS NULL OR n.gmsa = false) // Not gMSA, as it has primaryGroup to Domain Computers
AND (n.msa IS NULL OR n.msa = false) // Not MSA, as it has primaryGroup to Domain Computers
RETURN p
`,
	},
	"users-with-non-expiring-passwords": {
		Name:        "Users with non-expiring passwords",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
MATCH (u:User)
WHERE u.enabled = true
AND u.pwdneverexpires = true
RETURN u
LIMIT 100
`,
	},
	"users-with-passwords-not-rotated-in-over-1-year": {
		Name:        "Users with passwords not rotated in over 1 year",
		Description: "",
		Category:    "Active Directory Hygiene",
		Cypher: `
WITH 365 as days_since_change
MATCH (u:User)
WHERE u.pwdlastset < (datetime().epochseconds - (days_since_change * 86400))
AND NOT u.pwdlastset IN [-1.0, 0.0]
RETURN u
LIMIT 100
`,
	},
	"workstations-where-domain-users-can-rdp": {
		Name:        "Workstations where Domain Users can RDP",
		Description: "",
		Category:    "Dangerous Privileges",
		Cypher: `
MATCH p=(s:Group)-[:CanRDP]->(t:Computer)
WHERE s.objectid ENDS WITH '-513' AND NOT toUpper(t.operatingsystem) CONTAINS 'SERVER'
RETURN p
LIMIT 1000
`,
	},
}

// GetQuery returns the Cypher string for a given mode name
func GetQuery(mode string) (string, error) {
	if q, ok := Queries[mode]; ok {
		return q.Cypher, nil
	}
	return "", fmt.Errorf("unknown mode: %s", mode)
}
