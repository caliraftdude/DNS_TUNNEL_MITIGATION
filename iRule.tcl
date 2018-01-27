## required datagroup
### DNSTUNNEL_global_whitelist
### DNSTUNNEL_longQuery_whitelist
### DNSTUNNEL_longResp_whitelist
### DNSTUNNEL_nxdomain_whitelist
### DNSTUNNEL_resolLimit_whitelist
### DNSTUNNEL_unusualQuery_whitelist
### DNSTUNNEL_global_backlist

# v1.0 2017-12-14 
#    - Daniel : Initial Version
# v1.1 2017-12-14
#    - Anthony: increase timeout to 60s, 
#				change data group name, 
#				remove partition name
#				Add blacklist
# v1.3 20180124: remove CNAME from bypass logic



when RULE_INIT {
	
	array set static::DNSTUNNEL_cl_conns { }
	array set static::DNSTUNNEL_cl_resols { }
	array set static::DNSTUNNEL_cl_long_reqs { }
	array set static::DNSTUNNEL_cl_un_qtyps { }
	array set static::DNSTUNNEL_cl_nxdoms { }
	array set static::DNSTUNNEL_cl_long_resps { }
	array set static::DNSTUNNEL_blacklist { }
	
	if { [array exists static::DNSTUNNEL_subs_ip] } {
		unset -nocomplain static::DNSTUNNEL_subs_ip
	}
	
	array set static::DNSTUNNEL_subs_ip { }
	after 1000 -periodic {
		unset -nocomplain static::DNSTUNNEL_cl_conns
		unset -nocomplain static::DNSTUNNEL_cl_resols
		unset -nocomplain static::DNSTUNNEL_cl_long_reqs
		unset -nocomplain static::DNSTUNNEL_cl_un_qtyps
		unset -nocomplain static::DNSTUNNEL_cl_nxdoms
		unset -nocomplain static::DNSTUNNEL_cl_long_resps
		set this_second [clock second]
		
		foreach {key value} [array get static::DNSTUNNEL_blacklist] {
			if { $value < $this_second } {
				array unset static::DNSTUNNEL_blacklist $key
			}
		}
	}
	
}

when CLIENT_ACCEPTED {
    set key "[IP::remote_addr]"
}

when DNS_REQUEST {
    set qname [DNS::question name]
    set qtype [DNS::question type]
	set qnamelc [string tolower $qname]
	
	if { [info exists static::DNSTUNNEL_blacklist({$key})] } {
        call blacklisted $key
    }
	
	# Ignore A and AAAA Request types - cleaner logic this way
	if { ($qtype eq "A") or ($qtype eq "AAAA") } {
		return
	}
	
	if {[class match $qname ends_with DNSTUNNEL_global_backlist]} {
		drop
	}
	
    if { [info exists static::DNSTUNNEL_cl_resols({$key})] } {
        incr static::DNSTUNNEL_cl_resols({$key})
    } else {
        set static::DNSTUNNEL_cl_resols({$key}) 1
    }
	
	if { $static::DNSTUNNEL_cl_resols({$key}) > 100 } {
		set static::DNSTUNNEL_cl_resols({$key}) 0
		
		if { "" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_global_whitelist] } {
		} elseif { 
			"" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_resolLimit_whitelist] } {
		}
		else {
			call blacklisted $key
			call log "Client Resolutions Limit Exceeded:" $key
		}
    }
	
    if { [string length $qname] > 80 } {
        if { [info exists static::DNSTUNNEL_cl_long_reqs({$key})] } {
            incr static::DNSTUNNEL_cl_long_reqs({$key})
        } else {
            set static::DNSTUNNEL_cl_long_reqs({$key}) 1
        }
        
		if { $static::DNSTUNNEL_cl_long_reqs({$key}) > 10 } {
            set static::DNSTUNNEL_cl_long_reqs({$key}) 0
            
			if { "" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_global_whitelist] } {
            } elseif { 
				"" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_longQuery_whitelist] } {
            } else {
                call blacklisted $key
                call log "Client Long Request Limit Exceeded:<$qname> " $key
            }
        }
    }	
	
    if { ($qtype eq "NULL") or ($qtype eq "TXT")  or ($qtype eq "ANY") or ($qtype eq "WKS") } {
        if { [info exists static::DNSTUNNEL_cl_un_qtyps({$key})] } {
            incr static::DNSTUNNEL_cl_un_qtyps({$key})
        } else {
            set static::DNSTUNNEL_cl_un_qtyps({$key}) 1
        }
		
        if { $static::DNSTUNNEL_cl_un_qtyps({$key}) > 20 } {
            set static::DNSTUNNEL_cl_un_qtyps({$key}) 0
            
			if { "" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_global_whitelist] } {
            } elseif { 
				"" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_unusualQuery_whitelist] } {
            } else {
                call blacklisted $key
                call log "Client Long Request Limit Exceeded:<$qname>;<$qtype>" $key
            }
        }
    }	
	
}


when DNS_RESPONSE {
	set qtype [DNS::question type]
	# Ignore A and AAAA Request types - cleaner logic this way
	if { ($qtype eq "A")  or ($qtype eq "AAAA") } {
		return
	}
	
    set rcode [DNS::header rcode]
	
    if { $rcode eq "NXDOMAIN" || $rcode eq "SERVFAIL"} {
        if { [info exists static::DNSTUNNEL_cl_nxdoms({$key})] } {
            incr static::DNSTUNNEL_cl_nxdoms({$key})
        } else {
            set static::DNSTUNNEL_cl_nxdoms({$key}) 1
        }
		
        if { $static::DNSTUNNEL_cl_nxdoms({$key}) > 20 } {
            set static::DNSTUNNEL_cl_nxdoms({$key}) 0
			
			if { "" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_global_whitelist] } {
			} elseif { 
				"" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_nxdomain_whitelist] } {
			} else {
				call blacklisted $key
				call log "NX Domain Limit Exceeded:<$qname>" $key
			}
        }
    }	

    set length [DNS::len]
	
    if { $length > 200 } {
        if { [info exists static::DNSTUNNEL_cl_long_resps({$key})] } {
            incr static::DNSTUNNEL_cl_long_resps({$key})
            } else {
            set static::DNSTUNNEL_cl_long_resps({$key}) 1
        }
        if { $static::DNSTUNNEL_cl_long_resps({$key}) > 20 } {
            set static::DNSTUNNEL_cl_long_resps({$key}) 0
			if { "" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_global_whitelist] } {
			} elseif { 
				"" ne [class match -name -- $qnamelc ends_with DNSTUNNEL_longResp_whitelist] } {
			} else {
				call blacklisted $key
				call log "Response Length Limit Exceeded:<$qname>;<$length>" $key
			}
        }
    }
}

proc ip2hex {ip} {
	set octets [split $ip .]
	binary scan [binary format c4 $octets] H8 hex
	return 0x$hex
}

proc hex2ip {hex} {
	set r {}
	set bin [binary format I [expr {$hex}]]
	binary scan $bin c4 octets
	foreach octet $octets {
		lappend r [expr {$octet & 0xFF}]
	}
	return [join $r .]
}

proc ceil {a b} { 
	return [expr { ($a + $b + 1)/$b }] 
}

proc blacklisted {key} {
	set this_second [clock second]
	set static::DNSTUNNEL_blacklist({$key}) [expr { $this_second + 60 }]
		drop
		event disable all
}

proc log {log_info key} {
		set cl_info "($key)"
		log local0. "$log_info $cl_info"
}

proc logGen {log_line} {
		log local0. "$log_line"
}