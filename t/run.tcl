#!/usr/bin/env tclsh
# draugr test runner: tclsh t/run.tcl [path-to-draugr.tcl]

set here [file normalize [file dirname [info script]]]
set root [file dirname $here]
set dg [file join $root "draugr.tcl"]
if {[llength $argv] > 0} { set dg [file normalize [lindex $argv 0]] }

set pass 0
set fail {}

proc ck {label ok} {
    if {$ok} {
        incr ::pass
    } else {
        lappend ::fail $label
    }
}

# run the real cli as a subprocess; returns {exitcode stdout}
proc runcli {args} {
    set code 0
    if {[catch {exec {*}$args} out opts]} {
        if {[lindex $::errorCode 0] eq "CHILDSTATUS"} {
            set code [lindex $::errorCode 2]
        } else {
            return [list -1 $out]
        }
    }
    return [list $code $out]
}

# 1: load the internals without triggering main
set fd [open $dg r]
fconfigure $fd -translation binary
set src [read $fd]
close $fd
set marker {if {!$tcl_interactive}}
set idx [string last $marker $src]
if {$idx < 0} {
    puts "run: cannot locate the main guard in $dg"
    exit 2
}
eval [string range $src 0 [expr {$idx - 1}]]

# 2: the built-in assertion battery
set ::ST_PASS 0
set ::ST_FAIL {}
dg_selftest
ck "selftest battery ($::ST_PASS assertions)" [expr {[llength $::ST_FAIL] == 0}]

# 3: forge and scan through the real command line
set tclsh [info nameofexecutable]
set tmp [file join [file dirname $dg] ".tmp-run-[pid]"]
file delete -force $tmp
file mkdir $tmp

lassign [runcli $tclsh $dg forge [file join $tmp ev]] code out
ck "forge exits clean" [expr {$code == 0}]

lassign [runcli $tclsh $dg --no-color scan [file join $tmp ev clean_system.hiv] [file join $tmp ev tasks clean]] code out
ck "clean evidence exits 0" [expr {$code == 0}]
ck "clean evidence verdict clean" [expr {[string first "verdict: clean" $out] >= 0}]

lassign [runcli $tclsh $dg --no-color scan [file join $tmp ev dirty_system.hiv] [file join $tmp ev tasks dirty]] code out
ck "dirty evidence exits hostile" [expr {$code == 10}]
ck "dirty evidence verdict hostile" [expr {[string first "verdict: hostile" $out] >= 0}]
ck "masquerading task caught" [expr {[string first "S08" $out] >= 0}]
ck "hidden task caught" [expr {[string first "S03" $out] >= 0}]
ck "task requeue caught" [expr {[string first "S07" $out] >= 0}]

lassign [runcli $tclsh $dg --json scan [file join $tmp ev dirty_system.hiv]] code out
ck "json mode keeps the verdict" [expr {[string first "\"verdict\": \"hostile\"" $out] >= 0}]

file delete -force $tmp

if {[llength $fail] > 0} {
    puts "run: FAIL $::pass passed, [llength $fail] failed"
    foreach f $fail { puts "  FAIL $f" }
    exit 1
}
puts "run: PASS $pass checks"
exit 0
