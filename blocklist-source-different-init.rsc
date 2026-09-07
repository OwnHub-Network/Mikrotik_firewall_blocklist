# Small manifest imported before any address data.
:global blocklistSourceDifferentInit
:global blocklistSourceDifferentSources [:toarray ""]
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"tor_exits")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"spamhaus_drop")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"blocklist_de")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"cinsarmy")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"feodo")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"firehol_l1")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"firehol_l2")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"compromised_ips")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"ipsum")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"abuseipdb")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"binarydefense")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"ellio")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"greensnow")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"dshield_top")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"bruteforceblocker")
:set blocklistSourceDifferentSources ($blocklistSourceDifferentSources,"static_reserved")
:global blocklistSourceDifferentExpectedTotal 60449
$blocklistSourceDifferentInit sourceNames=$blocklistSourceDifferentSources expectedCount=16
