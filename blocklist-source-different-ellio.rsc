# source=ellio list=blocklist_ellio entries=13
:global blocklistSourceDifferentSync
:global blocklistSourceDifferentIps [:toarray ""]
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"18.231.254.122")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"23.0.2.46")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"34.132.109.190")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"68.18.58.68")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"74.117.76.171")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"99.48.218.194")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"138.137.190.198")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"141.54.160.10")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"162.42.158.34")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"171.76.96.74")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"174.48.226.166")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"190.109.132.34")
:set blocklistSourceDifferentIps ($blocklistSourceDifferentIps,"194.31.248.182")
$blocklistSourceDifferentSync sourceName="ellio" expectedCount=13
:set blocklistSourceDifferentIps
:global blocklistSourceDifferentSourceComplete "ellio"
