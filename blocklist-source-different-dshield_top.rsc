# source=dshield_top list=blocklist_dshield_top entries=9
:global blocklistSourceDifferentSync
:global blocklistSourceDifferentIps [:toarray ""]
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"3.131.209.36")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"5.189.160.21")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"62.167.236.39")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"89.248.163.200")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"173.249.4.73")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"173.249.33.72")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"204.236.133.68")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"207.180.192.205")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"207.180.192.206")
$blocklistSourceDifferentSync sourceName="dshield_top" expectedCount=9
:set blocklistSourceDifferentIps
:global blocklistSourceDifferentSourceComplete "dshield_top"
