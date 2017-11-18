rule anubi
{
	meta:
		author = "TJ Nelson (@REonFleek)"
		date = "2017-10-20"
		description = "Ransomware malware sample with the extension .anubi"
		filetype = "exe"
		reference0 = "https://www.bleepingcomputer.com/news/security/new-anubi-ransomware-in-the-wild/"
		sha256_0 = "3a047c557acde9adeb144508b367232a1043dd1e9c2230f8091a0323bf99ee7c"

	strings:
		$av0 = "/c \"wmic product where name=\"ESET NOD32 Antivirus\" call uninstall /nointeractive \""
		$av1 = "/c \"wmic product where name=\"Kaspersky Anti-Virus\" call uninstall /nointeractive \""
		$av2 = "/c \"wmic product where name=\"Kaspersky Internet Security\" call uninstall /nointeractive \""
		$av3 = "/c \"wmic product where name=\"Avira Connect\" call uninstall /nointeractive \""
		$av4 = "SOFTWARE\\Microsoft\\Windows Defender\\Reporting"
		$cmd0 = "Invmod of %d %% %d"
		$cmd1 = "Expected : %d"
		$cmd2 = "Result :"
		$cmd3 = "%08X%08X%c"
		$anti0 = "DisableAntiSpyware"
		$anti1 = "DisableRoutinelyTakingAction"
		$anti2 = "TaskbarNoNotification"
		$anti3 = "DisableNotificationCenter"
		$ransom0 = "Dele"
		$ransom1 = "te S"
		$ransom2 = "hado"
		$ransom3 = "ws /"
		$ransom4 = "All"
		$ransom5 = "/Qui"
		$ransom6 = "et &"


	condition:
		(uint16(0) == 0x5A4D) and (2 of ($av*)) and (3 of ($cmd*)) and (3 of ($anti*)) and (6 of ($ransom*))
}
