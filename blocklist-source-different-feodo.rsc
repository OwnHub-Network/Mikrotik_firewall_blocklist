# source=feodo list=blocklist_feodo entries=5
:global blocklistSourceDifferentSync
:global blocklistSourceDifferentIps [:toarray ""]
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"27.133.154.218")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"34.204.119.63")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"50.16.16.211")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"162.243.103.246")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"178.62.3.223")
$blocklistSourceDifferentSync sourceName="feodo" expectedCount=5
:set blocklistSourceDifferentIps
:global blocklistSourceDifferentSourceComplete "feodo"
