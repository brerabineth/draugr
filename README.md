# draugr

the corpse that walks again.

machines die. their autostarts do not. every run key, every winlogon hook,
every service and scheduled task a host left behind keeps firing long after
the breach report is closed. draugr reads the leftovers and tells you which
of the dead are still moving.

offline autopsy of windows autostart: registry hives and scheduled task xml,
pulled from a dead disk, a backup or a mounted image. no windows needed, no
agent, nothing executes, nothing leaves the machine.

## why

registry run keys are the most common persistence mechanism in real-world
intrusions (T1547.001) and scheduled tasks (T1053.005) are the cheapest way
to survive a reboot. the usual tools are a gui that wants a live host, or a
perl relic. draugr is the first hour, on a box you already have: point it at
the artifacts and read.

## what it reads

- registry hives: software, system, ntuser, sam — any regf file
- scheduled tasks: xml as written by schtasks /query /xml one
- both at once: draugr scan everything/

## the checks

hive side:

  A01  run / runonce entries
  A02  runonceex entries
  A03  cmd.exe AutoRun
  A04  winlogon Shell replaced
  A05  winlogon Userinit tampering
  A06  winlogon Taskman set
  A07  winlogon Notify packages
  A08  AppInit_DLLs / loader
  A09  IFEO Debugger hijack
  A10  LSA package tampering
  A11  BootExecute changed
  A12  service ImagePath
  A13  service ServiceDll
  A14  Active Setup StubPath
  A15  print monitor drivers
  A16  safeboot AlternateShell
  A17  invisible unicode in autostart names
  A18  logon script in winlogon

task side:

  S01  task command location
  S02  task suspicious command shape
  S03  hidden / privileged task
  S04  highest runlevel for scripts
  S05  logon or boot trigger with risky payload
  S06  machine-named task with script
  S07  task creating tasks
  S08  masquerading binary in task
  S09  empty action task

severities run low, med, high, crit. the verdict bands are clean, watch,
suspicious, hostile. benign autostarts are counted, not shouted.

## usage

  draugr scan <path>...        autopsy hives, task xml, whole directories
  draugr keys <hive>           walk a hive and print the key tree
  draugr dump <hive> <key>     print every value under one key path
  draugr forge <dir>           generate a clean and a dirty evidence set
  draugr selftest              52 built-in assertions
  draugr rules                 list the checks

flags: --json, --no-color (NO_COLOR is honored), --quiet, --min-severity.

exit codes a pipeline can gate on: 0 clean, 1 watch, 3 suspicious, 10
hostile, 2 error.

## try it in one line

  draugr forge /tmp/ev && draugr scan /tmp/ev

the forge writes two synthetic hives and two task sets — one clean, one
planted with the classics: encoded powershell in run, a debugger hijack on
defender, an appinit hook, a masquerading svhost service, a hidden guid task
that re-registers itself. the clean set stays quiet, so you can see what
silence looks like.

## requires

any tcl 8.6. one file. zero dependencies. no build step.

  tclsh draugr.tcl selftest

## layout

  draugr.tcl   the whole tool: regf reader, task reader, rules, forge, selftest
  t/run.tcl    test runner: the selftest battery plus end-to-end through the real cli

## notes

- the regf reader walks nk/vk cells, decodes utf-16, multi_sz, dword and
  qword, inline and pressed (compressed) value data, and big data records.
- malformed input is a finding, not a crash: truncated hives, corrupted
  cells and random bytes are reported and survived.
- value names and task identities carrying invisible unicode get flagged;
  autostart has a long history of homoglyph and zero-width tricks.
- nothing is executed, ever. evidence in, verdict out.

mit license.
