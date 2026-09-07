# Small manifest and direct init imported before any address data.
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
:global blocklistSourceDifferentExpectedTotal 60887
:if ([:len $blocklistSourceDifferentSources] != 16) do={
    :log error ("blocklist-source-different-init: expected-sources=16 actual=" . [:len $blocklistSourceDifferentSources])
    :error "source-list-count-mismatch"
}
:if ([:len [/interface list find where name="Interface_for_Blocklist"]] = 0) do={
    :if ([:len [/interface list find where name="WAN"]] > 0) do={
        /interface list add name="Interface_for_Blocklist" include="WAN" comment="Managed by blocklist-source-different"
        :log info "blocklist-source-different-init: created Interface_for_Blocklist with include=WAN"
    } else={
        /interface list add name="Interface_for_Blocklist" comment="Managed by blocklist-source-different"
        :log warning "blocklist-source-different-init: created empty Interface_for_Blocklist because WAN does not exist"
    }
}
:foreach ruleId in=[/ip firewall raw find where comment~"^Block_From_blocklist_"] do={
    :local rulePrefix "Block_From_blocklist_"
    :local ruleComment [/ip firewall raw get $ruleId comment]
    :local sourceName [:pick $ruleComment [:len $rulePrefix] [:len $ruleComment]]
    :local sourcePosition [:find $blocklistSourceDifferentSources $sourceName]
    :if ([:typeof $sourcePosition] = "nil") do={
        :local obsoleteList ("blocklist_" . $sourceName)
        /ip firewall raw remove $ruleId
        :local obsoleteEntries [/ip firewall address-list find where list=$obsoleteList]
        :if ([:len $obsoleteEntries] > 0) do={
            /ip firewall address-list remove $obsoleteEntries
        }
        :log info ("blocklist-source-different-init: removed stale source=" . $sourceName)
    }
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_tor_exits"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_tor_exits" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_tor_exits" src-address-list="blocklist_tor_exits"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_tor_exits" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_tor_exits" src-address-list="blocklist_tor_exits" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_tor_exits"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_spamhaus_drop"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_spamhaus_drop" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_spamhaus_drop" src-address-list="blocklist_spamhaus_drop"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_spamhaus_drop" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_spamhaus_drop" src-address-list="blocklist_spamhaus_drop" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_spamhaus_drop"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_blocklist_de"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_blocklist_de" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_blocklist_de" src-address-list="blocklist_blocklist_de"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_blocklist_de" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_blocklist_de" src-address-list="blocklist_blocklist_de" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_blocklist_de"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_cinsarmy"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_cinsarmy" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_cinsarmy" src-address-list="blocklist_cinsarmy"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_cinsarmy" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_cinsarmy" src-address-list="blocklist_cinsarmy" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_cinsarmy"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_feodo"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_feodo" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_feodo" src-address-list="blocklist_feodo"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_feodo" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_feodo" src-address-list="blocklist_feodo" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_feodo"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_firehol_l1"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_firehol_l1" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_firehol_l1" src-address-list="blocklist_firehol_l1"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_firehol_l1" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_firehol_l1" src-address-list="blocklist_firehol_l1" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_firehol_l1"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_firehol_l2"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_firehol_l2" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_firehol_l2" src-address-list="blocklist_firehol_l2"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_firehol_l2" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_firehol_l2" src-address-list="blocklist_firehol_l2" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_firehol_l2"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_compromised_ips"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_compromised_ips" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_compromised_ips" src-address-list="blocklist_compromised_ips"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_compromised_ips" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_compromised_ips" src-address-list="blocklist_compromised_ips" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_compromised_ips"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_ipsum"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_ipsum" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_ipsum" src-address-list="blocklist_ipsum"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_ipsum" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_ipsum" src-address-list="blocklist_ipsum" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_ipsum"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_abuseipdb"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_abuseipdb" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_abuseipdb" src-address-list="blocklist_abuseipdb"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_abuseipdb" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_abuseipdb" src-address-list="blocklist_abuseipdb" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_abuseipdb"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_binarydefense"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_binarydefense" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_binarydefense" src-address-list="blocklist_binarydefense"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_binarydefense" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_binarydefense" src-address-list="blocklist_binarydefense" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_binarydefense"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_ellio"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_ellio" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_ellio" src-address-list="blocklist_ellio"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_ellio" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_ellio" src-address-list="blocklist_ellio" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_ellio"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_greensnow"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_greensnow" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_greensnow" src-address-list="blocklist_greensnow"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_greensnow" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_greensnow" src-address-list="blocklist_greensnow" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_greensnow"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_dshield_top"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_dshield_top" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_dshield_top" src-address-list="blocklist_dshield_top"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_dshield_top" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_dshield_top" src-address-list="blocklist_dshield_top" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_dshield_top"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_bruteforceblocker"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_bruteforceblocker" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_bruteforceblocker" src-address-list="blocklist_bruteforceblocker"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_bruteforceblocker" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_bruteforceblocker" src-address-list="blocklist_bruteforceblocker" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_bruteforceblocker"
}
:if ([:len [/ip firewall raw find where comment="Block_From_blocklist_static_reserved"]] = 0) do={
    :local initialRawRules [/ip firewall raw find]
    :if ([:len $initialRawRules] = 0) do={
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_static_reserved" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_static_reserved" src-address-list="blocklist_static_reserved"
    } else={
        :local placeBeforeId [:pick $initialRawRules 0]
        /ip firewall raw add action=drop chain=prerouting comment="Block_From_blocklist_static_reserved" disabled=no in-interface-list="Interface_for_Blocklist" log=no log-prefix="RAW_drop_from_blocklist_static_reserved" src-address-list="blocklist_static_reserved" place-before=$placeBeforeId
    }
    :log info "blocklist-source-different-init: created rule Block_From_blocklist_static_reserved"
}
:if ([/ip firewall raw print count-only where comment~"^Block_From_blocklist_"] != 16) do={
    :log error ("blocklist-source-different-init: expected-rules=16 actual=" . [/ip firewall raw print count-only where comment~"^Block_From_blocklist_"])
    :error "raw-rule-count-mismatch"
}
:global blocklistSourceDifferentInitComplete true
:log info "blocklist-source-different-init: complete sources=16"
