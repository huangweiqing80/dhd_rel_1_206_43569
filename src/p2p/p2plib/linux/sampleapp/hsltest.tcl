#!/usr/bin/tclsh

#
# Test driver for the WiFi-Direct HSL
#
# Usage:
#  On server console, launch HSL interactive app using this script:
#    ./hsltext.tcl
#
#  On client console:
#    echo -n "<some command>" | nc localhost 2222 || echo status,ERROR,reason,Server_Dead
#
# Installation dependencies:
#   yum install expect
#
# References on expect:
#  O'Reilly "Exploring Expect"
#  man expect
#  http://www.cotse.com/dlf/man/expect/index.htm
#  http://expect.sourceforge.net/
#  http://expect.nist.gov/
#  http://www.tcl.tk/man/expect5.31/expect.1.html
#  http://wiki.tcl.tk/201
#
package require Expect

#####################################################
#
# Variable initialization
#

set the_app "./bcmp2papp"
set the_socket 2222
set the_prompt "\n> "
set timeout_app_start 5
set timeout_command 60

# Controls whether to show the expect dialogue
log_user 1

# Collection of socket handles
global s
global deviceAddress

#####################################################
#
# Subroutines
#

# Send debug trace messages to stderr.
proc log {str} {
	global argv0
	puts stderr "$argv0 - $str"
}

# Handle a new socket connection
proc Accept {sock addr port} {
	global s
	log "Accepted $sock from $addr port $port"
	set s(addr,$sock) [list $addr $port]
	fconfigure $sock -buffering line -translation lf
	fileevent $sock readable [list HandleConnect $sock]
}

# Handle some input
proc HandleConnect {sock} {
	global s
	
	# If end of input, do nothing
	if {[eof $sock]} {
		return
	}

	# Get input, handling abnormal connection drop
	if {[catch {gets $sock line} result]} {
		log "Closing $s(addr,$sock) due to: $result"
	} else {
		HandleRequest $sock "$line"
		log "Normal close $s(addr,$sock)"
	}
	close $sock
	unset s(addr,$sock)
}

# Handle one line of input
#
# TODO: Translate Sigma commands to HSL commands here
#
proc HandleRequest {sock line} {
	global deviceAddress
	# Reject blank lines
	if {[regexp {^\s*$} "$line"]} {
		puts $sock "status,INVALID"
		return
	}

	# Notify that we expect the command is valid so we'll start to execute it.
	puts $sock "status,RUNNING"

	# Translate line to HSL commands and read back HSL result, translate back to Sigma messages
	if {[regexp -nocase "sta_get_p2p_dev_address,(.*),(.*)" $line match intf intfname]} {
	    # hard code the mac address for now
	    #puts $sock "status,COMPLETE,DevID,02:25:56:00:ca:f1"
	    #return    

    	    set cmd "dev_addr\n"
	    set txt [DoCmd $cmd]
	    if {[regexp {Unrecognized command} $txt]} {
		puts $sock "status,INVALID"
		return
	    } elseif {[regexp -nocase "Device address: (\[0-9|a-f]\[0-9|a-f]:\[0-9|a-f]\[0-9|a-f]:\[0-9|a-f]\[0-9|a-f]:\[0-9|a-f]\[0-9|a-f]:\[0-9|a-f]\[0-9|a-f]:\[0-9|a-f]\[0-9|a-f]).*" $txt match devAddress]} {
		puts $sock "status,COMPLETE,DevID,$devAddress"
		exec echo $devAddress > /tmp/p2pdevaddr.txt
		set deviceAddress $devAddress
	    } else {
		# hard code this one back to the request
		puts $sock "status,COMPLETE,DevID,02:25:56:00:ca:f1"
	    }
	} elseif { [regexp -nocase "sta_set_p2p,interface,(.*),(.*),(.*)" $line match intfname para2_name para2_value] } {
	    if { [string equal -nocase $para2_name "oper_chn"]} {
		set txt [DoCmd "op_chan $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } elseif { [string equal -nocase $para2_name "listen_chn"]} {
		set txt [DoCmd "listen_chan $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } elseif { [string equal -nocase $para2_name "intent_val"]} {
		set txt [DoCmd "intent $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } elseif { [string equal -nocase $para2_name "p2p_mode"]} {
		if { [string equal -nocase $para2_value "discover"] } {
		    set txt [DoCmd "discovery 1"]
			after 10000
		    CheckStatusAndReturnComplete $sock $txt
		} elseif {[string equal -nocase $para2_value "disable"]} {
		    set txt [DoCmd "discovery 0"]
		    CheckStatusAndReturnComplete $sock $txt
		} elseif { [string equal -nocase $para2_value "listen"] } {
		    set txt [DoCmd "discovery 1"]
			after 10000
		    CheckStatusAndReturnComplete $sock $txt
		} elseif { [string equal -nocase $para2_value "idle"] } {
		    set txt [DoCmd "discovery 1"]
		    CheckStatusAndReturnComplete $sock $txt
		} else {
		    puts $sock "status,INVALID"
		    #set txt [DoCmd "p2p_mode $para2_value"]
		    #CheckStatusAndReturnComplete $sock $txt
		}
	    } elseif { [string equal -nocase $para2_name "ssid"]} {
		set txt [DoCmd "ssid $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } elseif { [string equal -nocase $para2_name "persistent"]} {
		set txt [DoCmd "persistent $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } elseif { [string equal -nocase $para2_name "intra_bss"]} {
		set txt [DoCmd "intra_bss $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } elseif { [string equal -nocase $para2_name "noa_duration"]} {
		set txt [DoCmd "go_noa_duration $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } elseif { [string equal -nocase $para2_name "noa_interval"]} {
		set txt [DoCmd "go_noa_interval $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } elseif { [string equal -nocase $para2_name "noa_count"]} {
		set txt [DoCmd "go_noa_count $para2_value"]
		CheckStatusAndReturnComplete $sock $txt
	    } else {
		puts $sock "status,INVALID"
	    }

	} elseif {[regexp -nocase "sta_p2p_connect,interface,(.*),p2pdevid,(.*)" $line match intfname dev_id]} {
	    set txt [DoCmd "group_formation $dev_id"]
	    after 10000
	    CheckStatusAndReturnComplete $sock $txt
	} elseif {[regexp -nocase "sta_send_p2p_invitation_req,interface,(.*),p2pdevid,(.*),groupid,(.*),reinvoke,(.*)" $line match intfname dev_id group_id reinvoke]} {
	    if { $reinvoke == 0 } {
	        set txt [DoCmd "discovery 1"]
	        after 10000
	        set txt [DoCmd "invite_to_device $dev_id"]
	        after 20000
            } else {
	      if {[regexp -nocase "(.*) (.*)" $group_id match dev_id2 ssid]} {
	         if {[regexp -nocase ".*$dev_id.*" $group_id match]} {
	           set txt [DoCmd "invite_to_go $ssid"]
	           after 20000
                 } else {
	           set txt [DoCmd "invite_to_client $dev_id"]
	           after 20000
                 }
              }
            }
	    CheckStatusAndReturnComplete $sock $txt
	} elseif {[regexp -nocase "sta_start_autonomous_go,interface,(.*),oper_chn,(.*),SSID,(.*)" $line match intfname operChan p2pSsid]} {
	    set txt [DoCmd "op_chan $operChan"]
	    set txt [DoCmd "create_group DIRECT-yu$p2pSsid"]
	    after 5000
	    set txt [DoCmd "group_id"]

	    if {[regexp -nocase "(.*) DIRECT-yu.*" $txt match mac1] } {
		exec echo "$mac1 DIRECT-yu$p2pSsid" > /tmp/p2pgrpid.txt
	    }
            set txt [DoCmd "wps_open"]
	    CheckStatusAndReturnComplete $sock $txt
	} elseif {[regexp -nocase "sta_p2p_start_group_formation,interface,(.*),p2pdevid,(.*),intent_val,(.*),init_go_neg,(.*)" $line match intfname dev_id intentVal startGO ]} {
	    set txt [DoCmd "intent $intentVal"]
	    if { $startGO == 1 } {
		puts "###################### Start GO NEG ##########################"
	    	 set txt [DoCmd "group_formation $dev_id"]
		 after 10000
	   	 if {[regexp {Invalid params} $txt] } {
			puts $sock "status,INVALID"
			return
	   	 } else {
                        set txt [DoCmd "group_id"]
                        exec echo "$txt" > /tmp/p2p_grpid.txt
			#set txt [DoCmd "status"]
			#if {[regexp "is GO '(.*)'.*" $txt match gossid]} {
			#	puts $sock "status,COMPLETE,result,GO,groupid,02:25:56:00:4A:F1_$gossid"
			#	exec echo "GO" > /tmp/p2pgo.txt
			#} elseif {[regexp ".*STA.*" $txt match]} {
			#	puts $sock "status,COMPLETE,result,CLIENT,groupid,02:25:56:00:4A:F1_DIRECT"
			#	exec echo "CLIENT" > /tmp/p2pgo.txt
			#} else {
			#	puts $sock "status,ERROR"
			#}
	   	 }
    	    } else {
		# stay in discovery mode if not and wait for GO neg request to arrive
		set txt [DoCmd "discovery 1"]
		after 10000
		# return null Go/Client and groupid
		puts $sock "status,COMPLETE,result,,groupid,"
	    }
	} elseif {[regexp -nocase "sta_p2p_dissolve,interface,(.*),groupid,(.*)" $line match intfname  group_id]} {
	    set txt [DoCmd "disconnect"]
	    if {[regexp {Unrecognized command} $txt]} {
		puts $sock "status,INVALID"
		return
	    } elseif {[regexp -nocase ".*success.*" $txt match]} {
		puts $sock "status,COMPLETE"
	    } else {
		puts $sock "status,ERROR"
	    }
        } elseif {[regexp -nocase "sta_send_p2p_invitation_req,interface,(.*),p2pdevid,(.*),groupid,(.*)" $line match intfname dev_id group_id]} {
	    set txt [DoCmd "sendinvreq $dev_id"]
	    if {[regexp {Unrecognized command} $txt]} {
		puts $sock "status,INVALID"
		return
	    } elseif {[regexp -nocase ".*success.*" $txt match]} {
		puts $sock "status,COMPLETE"
	    } else {
		puts $sock "status,ERROR"
	    }
        } elseif {[regexp -nocase "sta_accept_p2p_invitation_req,interface,(.*),p2pdevid,(.*)" $line match intfname dev_id]} {
	    puts $sock "status,INVALID"
        } elseif {[regexp -nocase "sta_send_p2p_provision_dis_req,interface,(.*),p2pdevid,(.*),configmethod,(.*)" $line match intfname dev_id config_method]} {
	    set txt [DoCmd "send_prov_discovery $dev_id $config_method"]
	    if {[regexp {Unrecognized command} $txt]} {
		puts $sock "status,INVALID"
		return
	    } elseif {[regexp -nocase ".*success.*" $txt match]} {
		puts $sock "status,COMPLETE"
	    } else {
		puts $sock "status,ERROR"
	    }
        } elseif {[regexp -nocase "sta_set_wps_pbc,interface,(.*)" $line match intfname ]} {
	    set txt [DoCmd "wps_pbc"]
	    if {[regexp {Unrecognized command} $txt]} {
		puts $sock "status,INVALID"
		return
	    } elseif {[regexp -nocase ".*success.*" $txt match]} {
		puts $sock "status,COMPLETE"
	    } else {
		puts $sock "status,ERROR"
	    } 
        } elseif {[regexp -nocase "sta_wps_read_pin,interface,(.*)" $line match intfname]} {
	    set txt [DoCmd "wps_pin"]
	    if {[regexp {Unrecognized command} $txt]} {
		puts $sock "status,INVALID"
		return
	    } elseif {[regexp -nocase "WPS pin: (.*)\n.*success.*" $txt match wpsPin]} {
		exec echo $wpsPin > /tmp/p2ppin.txt
		puts $sock "status,COMPLETE"
	    } else {
		puts $sock "status,ERROR"
	    } 
        } elseif {[regexp -nocase "sta_wps_enter_pin,interface,(.*),pin,(.*)" $line match intfname pin_str]} {
		set txt [DoCmd "wps_pin $pin_str"]
		puts $sock "status,COMPLETE"
        } elseif {[regexp -nocase "sta_get_psk,interface,(.*)" $line match intfname]} {

        } elseif  {[regexp -nocase "sta_get_info" $line match]} {
	    puts $sock "status,COMPLETE,company,Broadcom,chipset,4322"
        } elseif  {[regexp -nocase "device_get_info" $line match]} {
	    puts $sock "status,COMPLETE,vendor,Broadcom,model,4322,version,PF3.0"
        } elseif  {[regexp -nocase "ca_get_version" $line match]} {
	    puts $sock "status,COMPLETE,version,1.3"
	    exec echo "1.3" > /tmp/p2pver.txt
        } elseif  {[regexp -nocase "sta_p2p_reset,interface,(.*)" $line match intfname]} {
	    # not doing anything right now, just return ok
	    set txt [DoCmd "discovery 0"]
	    set txt [DoCmd "reset"]
	    puts $sock "status,COMPLETE"
        } elseif  {[regexp -nocase "device_list_interfaces,interfaceType,802.11" $line match]} {
	    # not doing anything, return wl0.1 as p2p interface
	    puts $sock "status,COMPLETE,interfaceType,802.11,interfaceID,wl0.1"
        } else {
	    # Execute the command with no translation
	    set txt [DoCmd $line]
	    CheckStatusAndReturnComplete $sock $txt
	}
}

#send back message of status RUNNING
proc CheckStatusAndReturnComplete {sock txt} {
    # Catch rejected commands. The above translation should have avoided this.
    if {[regexp {Unrecognized command} $txt]} {
	puts $sock "status,INVALID"
	return
    } elseif {[regexp -nocase ".*success.*" $txt match]} {
	puts $sock "status,COMPLETE"
    } else {
	puts $sock "status,ERROR"
    }
}

# Send a command to HSL, and return the output.
proc DoCmd {cmd} {
	global the_app
	global the_prompt
	global timeout
	global timeout_command
	set timeout $timeout_command
	switch [catch { 
		exp_send "$cmd\n"
		expect {
			"$the_prompt" 	{ }
			eof				{ return "$the_app exited"}
			timeout			{ return "no prompt" }
		}
	} result] {
		0 {	# Normal completion
			log "Command succeeded"
		}
		1 {	# Error case
			log "Command failed: $result"
			return "status,ERROR"
		}
		2 { # 'return' case
			log "Command failed because $result"
			return "status,ERROR"
		}
	}
	# Now process the text from expect, after the command, before the next prompt.
	set txt $expect_out(buffer)
	regsub -all {\r} "$txt" "" txt
	regsub "$cmd\n" "$txt" "" txt
	regsub "$the_prompt" "$txt" "" txt

	# Pass result back to the caller.
	return "$txt"
}

#####################################################
#
# Main program
#

# Launch the app to test
set timeout $timeout_app_start

if [catch { 
	# Tcl Gotcha: Use eval to split up the argv list for spawn (or exec).
	# removed the --cli option
	set app_pid [eval {exp_spawn $the_app } $argv]
	expect {
		"$the_prompt"		{ log "Ready"; }
		eof      			{ log "$the_app exited"; exit 1; }
		timeout      		{ log "$the_app failed to prompt. Aborting."; exit 1; }
	}
} result] {
	log "Launch $the_app failed: $result"
	exit 1
} else {
	log "Launched $the_app, pid $app_pid, id $spawn_id"
}

# Initialize the listen socket, so it will call Accept to handle connections
set s(main) [socket -server Accept $the_socket]


# Finally, run the event loop until the spawned HSL app terminates

# Option (1)
# While running the event loop, also allow direct user interaction with the hsl app.
# Note: The "spawn id .+ not open" message is normal when the hsl app exits, anything else is abnormal.
if [catch { interact } result] {
	if {![regexp "interact: spawn id .+ not open" "$result"]} {
		log "Abnormal termination: $result"
		exit 1;
	}
}
log "Bye."
exit 0;	# Normal exit, the app terminated

# Option (2)
# Use vwait to run the event loop forever. 
# Problem: Won't exit when hsl app exits.
# Advantage: Very simple. Use this if the interact causes trouble.
#vwait forever
#exit 0

# Option (3)
# Use wait to wait and then exit when the hsl app exits.
# Problem: Doesn't allow socket server to run.
#wait
#exit 0
