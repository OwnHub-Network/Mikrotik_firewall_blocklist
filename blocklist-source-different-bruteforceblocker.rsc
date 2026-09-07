# source=bruteforceblocker list=blocklist_bruteforceblocker entries=1
:global blocklistSourceDifferentSync
:global blocklistSourceDifferentIps [:toarray ""]
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"172.174.245.26")
$blocklistSourceDifferentSync sourceName="bruteforceblocker" expectedCount=1
:set blocklistSourceDifferentIps
:global blocklistSourceDifferentSourceComplete "bruteforceblocker"
