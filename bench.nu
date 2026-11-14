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

# Times `count` round trips of one line through `cat` on the host, in
# milliseconds. With `busy` an upload runs beside it on the same connection.
def echoes [command: string, count: int, busy: bool] {
   let script = r#'
      tool=$1 count=$2 busy=$3

      if [ "$busy" = true ]; then
         head -c 1000000000000 /dev/zero | $tool wc -c > /dev/null 2>&1 &
         load=$!
         sleep 2
      fi

      coproc CAT { exec $tool cat 2> /dev/null; }
      echo warm >&"${CAT[1]}"
      read -r -t 20 -u "${CAT[0]}" line || exit 1

      for ((round = 0; round < count; round++)); do
         start=${EPOCHREALTIME/./}
         echo ping >&"${CAT[1]}"
         read -r -t 20 -u "${CAT[0]}" line || exit 1
         echo $((${EPOCHREALTIME/./} - start))
         sleep 0.05
      done

      [ -n "$load" ] && kill "$load"
      kill "$CAT_PID"
   '#

   let run = ^bash -c $script bash $command $count $busy | complete

   if $run.exit_code != 0 {
      error make { msg: $"no echo through: ($command)" }
   }

   $run.stdout | lines | each {|micros| ($micros | into int) / 1000 }
}

def main [
   host: string # The server, as both tools name it.
   --size: filesize = 1GB # How much each transfer moves.
   --runs: int = 5 # How many rounds to take the median of.
   --identity: path # A key file that logs in without a prompt.
   --echoes: int = 100 # How many keystroke round trips to time.
   --qsh: string = "qsh" # The qsh command, with a port if it needs one.
   --ssh: string = "ssh"
] {
   let bytes = $size | into int
   let key = if $identity == null { "" } else { $" -i ($identity)" }

   let sockets = mktemp --directory

   let tools = [[name base]; [qsh $"($qsh)($key)"] [ssh $"($ssh)($key)"]] | each {|tool|
      let shared = [
         "-o ControlMaster=auto"
         $"-o ControlPath=($sockets)/($tool.name)"
         "-o ControlPersist=60"
      ] | str join " "

      {
         name: $tool.name
         command: $"($tool.base) -o ControlPath=none ($host)"
         shared: $"($tool.base) ($shared) ($host)"
         close: $"($tool.base) ($shared) -O exit ($host)"
      }
   }

   let samples = 1..$runs | each {|round|
      $tools | each {|tool|
         print --stderr $"round ($round) of ($runs), ($tool.name)"

         let connect = timed $"($tool.command) true"
         let upload = moved $"head -c ($bytes) /dev/zero | ($tool.command) wc -c" $bytes
         let download = moved $"($tool.command) head -c ($bytes) /dev/zero | wc -c" $bytes

         {
            tool: $tool.name
            connect_ms: ($connect.wall * 1000)
            up_gbit: $upload.gbit
            up_cpu_s_gb: $upload.cpu_per_gb
            down_gbit: $download.gbit
            down_cpu_s_gb: $download.cpu_per_gb
         }
      }
   } | flatten

   print ($samples | group-by tool | items {|name, rows|
      $rows | reject tool | math median | insert tool $name | move tool --first
   })

   # A shell and a transfer on one connection, which is where a lost packet
   # of the transfer can hold up the shell.
   let latency = $tools | each {|tool|
      print --stderr $"keystrokes, ($tool.name)"
      timed $"($tool.shared) true" | ignore

      let idle = echoes $tool.shared $echoes false
      let busy = echoes $tool.shared $echoes true
      timed $tool.close | ignore

      {
         tool: $tool.name
         idle_ms: ($idle | math median)
         busy_ms: ($busy | math median)
         busy_p95_ms: ($busy | sort | get (($echoes * 95 / 100 | into int) - 1))
         busy_max_ms: ($busy | math max)
      }
   }

   rm --recursive $sockets
   $latency
}
