#!/usr/bin/env nu

# Compares qsh with ssh against one host that runs both qshd and sshd.
#
# Every round runs each tool once per test, so drifting load on either
# machine hits both. The login has to work without a prompt, a PIN or a
# touch, or the wait for a person ends up in the numbers.

# Runs a bash pipeline and returns what it printed, how long it took and
# how much CPU time this side spent on it.
def timed [pipeline: string] {
   let run = ^bash -c $"TIMEFORMAT='%R %U %S'; time \( ($pipeline) 2>/dev/null \)" | complete
   let times = $run.stderr | str trim | split row " " | each { into float }

   if $run.exit_code != 0 or ($times | length) != 3 {
      error make { msg: $"failed: ($pipeline)" }
   }

   { output: ($run.stdout | str trim), wall: $times.0, cpu: ($times.1 + $times.2) }
}

# Returns the rate and the CPU cost of a transfer of `bytes`. The pipeline
# has to print how many bytes arrived, which is checked.
def moved [pipeline: string, bytes: int] {
   let run = timed $pipeline

   if ($run.output | into int) != $bytes {
      error make { msg: $"($run.output) of ($bytes) bytes arrived: ($pipeline)" }
   }

   { gbit: ($bytes * 8 / $run.wall / 1e9), cpu_per_gb: ($run.cpu / ($bytes / 1e9)) }
}

def main [
   host: string # The server, as both tools name it.
   --size: filesize = 1GB # How much each transfer moves.
   --runs: int = 5 # How many rounds to take the median of.
   --identity: path # A key file that logs in without a prompt.
   --qsh: string = "qsh -S none" # The qsh command, with a port if it needs one.
   --ssh: string = "ssh -o ControlPath=none"
] {
   let bytes = $size | into int
   let key = if $identity == null { "" } else { $" -i ($identity)" }

   let tools = [
      { name: "qsh", command: $"($qsh)($key) ($host)" }
      { name: "ssh", command: $"($ssh)($key) ($host)" }
   ]

   let samples = 1..$runs | each {|round|
      $tools | each {|tool|
         print --stderr $"round ($round) of ($runs), ($tool.name)"

         let connect = timed $"($tool.command) true"
         let upload = moved $"head -c ($bytes) /dev/zero | ($tool.command) wc -c" $bytes
         let download = moved $"($tool.command) head -c ($bytes) /dev/zero | wc -c" $bytes

         {
            tool: $tool.name
            connect_ms: ($connect.wall * 1000)
            upload_gbit: $upload.gbit
            upload_cpu_s_per_gb: $upload.cpu_per_gb
            download_gbit: $download.gbit
            download_cpu_s_per_gb: $download.cpu_per_gb
         }
      }
   } | flatten

   $samples | group-by tool | items {|name, rows|
      $rows | reject tool | math median | insert tool $name | move tool --first
   }
}
