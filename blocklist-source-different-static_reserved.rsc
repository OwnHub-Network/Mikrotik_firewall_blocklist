# source=static_reserved list=blocklist_static_reserved entries=1
:global blocklistSourceDifferentSync
:global blocklistSourceDifferentIps [:toarray ""]
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"240.0.0.0/4")
$blocklistSourceDifferentSync sourceName="static_reserved" expectedCount=1
:set blocklistSourceDifferentIps
:global blocklistSourceDifferentSourceComplete "static_reserved"
