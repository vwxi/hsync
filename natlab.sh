#!/usr/bin/env bash
# natlab -- single-host NAT hole-punching lab
# Topology: one public server + two clients, each behind its own configurable NAT.
#
#   server 10.0.0.10 (+ alt 10.0.0.11)
#      |
#   brpub (public L2, 10.0.0.0/24) --- routerA (WAN 10.0.0.2) --- clientA 192.168.1.100
#                                 \- routerB (WAN 10.0.0.3) --- clientB 192.168.2.100
#
# Everything lives in network namespaces on one host; veth pairs wire them up
# and nftables implements the per-router NAT behaviour.
set -Eeuo pipefail

# ---------------- error handling ----------------
# ERR trap prints a stack trace (file:line + function + the failing source line)
# whenever any command fails, so you can see exactly what broke and where.
on_err() {
  local rc=$?
  trap - ERR                                          # disable after capturing rc (avoid recursion)
  echo "natlab: command failed (exit $rc). Stack (most recent first):" >&2
  local i=0 out ln fn fl src
  while out=$(caller "$i" 2>/dev/null); do
    [ -z "$out" ] && break
    read -r ln fn fl <<< "$out"
    src=$(sed -n "${ln}p" "${fl:-$0}" 2>/dev/null | sed 's/^[[:space:]]*//' || true)
    printf '   %s:%s  %s()' "${fl##*/}" "$ln" "${fn:-main}" >&2
    [ -n "$src" ] && printf '  -> %s' "$src" >&2
    printf '\n' >&2
    i=$((i+1)); [ "$i" -ge 20 ] && break
  done
  echo "  hint: re-run with --verbose to trace every command (sudo $0 --verbose <cmd>)" >&2
  exit "$rc"
}
trap on_err ERR

# ---------------- config ----------------
declare -A WAN_IP=(   [routerA]=10.0.0.2      [routerB]=10.0.0.3 )
declare -A LAN_IP=(   [routerA]=192.168.1.1   [routerB]=192.168.2.1 )
declare -A CLIENT_IP=( [routerA]=192.168.1.100 [routerB]=192.168.2.100 )
declare -A WAN_IF=(   [routerA]=routerA-pub-n [routerB]=routerB-pub-n )
declare -A LAN_IF=(   [routerA]=routerA-lan   [routerB]=routerB-lan )
declare -A CLIENT_IF=( [clientA]=clientA-veth [clientB]=clientB-veth )
declare -A CLIENT_NS=( [routerA]=clientA      [routerB]=clientB )
DEFAULT_TYPE=restricted          # common home-router behaviour; punch works when both sides punch

STATEDIR=/run/natlab
TYPES_FILE=$STATEDIR/types
STUN_PID=$STATEDIR/stun.pid

err()       { echo "natlab: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || err "must run as root (try sudo)"; }
up_and()    { ip netns list | grep -qw routerA || err "topology is down; run: sudo $0 up"; }
router_of() { case "$1" in A|a) echo routerA;; B|b) echo routerB;; *) err "router must be A or B (got '$1')";; esac; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || err "missing required command '$1' (apt install $2)"; }

# ---------------- topology ----------------
newns()  { ip netns add "$1"; ip -n "$1" link set lo up; }
# plug <ns> <ip/cidr> : veth pair from brpub into the namespace
plug()   { ip link add "$1-pub" type veth peer name "$1-pub-n"
           ip link set "$1-pub" master brpub; ip link set "$1-pub" up
           ip link set "$1-pub-n" netns "$1"
           ip -n "$1" addr add "$2" dev "$1-pub-n"; ip -n "$1" link set "$1-pub-n" up; }
# mkpair <router> <router-lan-ip> <client-ns> <client-ip> <gw>
mkpair() { local r=$1 lanip=$2 cns=$3 cip=$4 gw=$5
           ip link add "${LAN_IF[$r]}" type veth peer name "${CLIENT_IF[$cns]}"
           ip link set "${LAN_IF[$r]}" netns "$r"
           ip link set "${CLIENT_IF[$cns]}" netns "$cns"
           ip -n "$r"   addr add "$lanip" dev "${LAN_IF[$r]}"
           ip -n "$cns" addr add "$cip"   dev "${CLIENT_IF[$cns]}"
           ip -n "$r"   link set "${LAN_IF[$r]}"   up
           ip -n "$cns" link set "${CLIENT_IF[$cns]}" up
           ip -n "$cns" route add default via "$gw"; }

cmd_up() {
  need_root
  require_cmd ip iproute2
  require_cmd nft nftables
  cmd_down >/dev/null 2>&1 || true
  mkdir -p "$STATEDIR"; : > "$TYPES_FILE"

  ip link add brpub type bridge; ip link set brpub up

  newns server;  plug server 10.0.0.10/24
  ip -n server addr add 10.0.0.11/24 dev server-pub-n    # alt IP for STUN behaviour tests

  newns routerA; plug routerA "${WAN_IP[routerA]}/24"
  newns routerB; plug routerB "${WAN_IP[routerB]}/24"

  newns clientA; newns clientB
  mkpair routerA "${LAN_IP[routerA]}/24" clientA "${CLIENT_IP[routerA]}" "${LAN_IP[routerA]}"
  mkpair routerB "${LAN_IP[routerB]}/24" clientB "${CLIENT_IP[routerB]}" "${LAN_IP[routerB]}"

  for r in routerA routerB; do ip netns exec "$r" sysctl -qw net.ipv4.ip_forward=1; done

  set_nat routerA "$DEFAULT_TYPE"
  set_nat routerB "$DEFAULT_TYPE"
  echo "topology up. default NAT: A=$DEFAULT_TYPE B=$DEFAULT_TYPE"
  echo "  change with:  sudo $0 nat A <none|fullcone|restricted|symmetric>"
  echo "  classify NAT: sudo $0 stun start && sudo $0 test"
  echo "  run your code: sudo $0 run clientA ./your-client --stun 10.0.0.10:3478"
}

cmd_down() {
  need_root
  cmd_stun stop >/dev/null 2>&1 || true
  for ns in server routerA routerB clientA clientB; do ip netns del "$ns" 2>/dev/null || true; done
  ip link del brpub 2>/dev/null || true
  rm -rf "$STATEDIR" 2>/dev/null || true
  echo "topology down."
}

# ---------------- NAT configuration ----------------
# set_nat <router> <none|fullcone|restricted|symmetric>
set_nat() {
  local r=$1 type=${2:-} wan=${WAN_IF[$r]} cip=${CLIENT_IP[$r]} wip=${WAN_IP[$r]}
  ip netns exec "$r" nft delete table inet nat 2>/dev/null || true
  case "$type" in
    none) : ;;                       # forwarding only, no NAT (baseline)
    fullcone) ip netns exec "$r" nft -f - <<EOF        # EIM + EIF
table inet nat {
  chain postrouting { type nat hook postrouting priority srcnat; policy accept;
    oifname "$wan" snat to $wip }
  chain prerouting  { type nat hook prerouting  priority dstnat; policy accept;
    iifname "$wan" dnat to $cip }
}
EOF
;;
    restricted) ip netns exec "$r" nft -f - <<EOF       # EIM + addr/port-dep filtering
table inet nat {
  chain postrouting { type nat hook postrouting priority srcnat; policy accept;
    oifname "$wan" snat to $wip }
}
EOF
;;
    symmetric) ip netns exec "$r" nft -f - <<EOF        # APDM + APDF (random external port)
table inet nat {
  chain postrouting { type nat hook postrouting priority srcnat; policy accept;
    oifname "$wan" masquerade random }
}
EOF
;;
    *) err "unknown NAT type '$type' (use: none|fullcone|restricted|symmetric)";;
  esac
  [ -f "$TYPES_FILE" ] && { sed -i "/^$r /d" "$TYPES_FILE"; echo "$r $type" >> "$TYPES_FILE"; }
}

cmd_nat() {
  need_root; up_and
  [ $# -ge 2 ] || err "usage: $0 nat <A|B> <none|fullcone|restricted|symmetric>"
  local r; r=$(router_of "$1"); local type=$2
  set_nat "$r" "$type"
  echo "$r (client ${CLIENT_NS[$r]}) NAT -> $type"
}

# ---------------- observation ----------------
cmd_status() {
  need_root
  ip netns list | grep -qw routerA || { echo "topology is down."; exit 0; }
  echo "== namespaces =="; ip netns list
  echo "== NAT types ==";  awk '{print "  "$1" -> "$2}' "$TYPES_FILE" 2>/dev/null
  for r in routerA routerB; do
    echo "== $r :: conntrack (internal<->external mappings) =="
    ip netns exec "$r" conntrack -L 2>/dev/null | sed 's/^/  /' || echo "  (none)"
  done
}

cmd_test() {
  need_root; up_and
  echo "== reachability =="
  ip netns exec clientA ping -c1 -W1 10.0.0.10 >/dev/null && echo "  clientA -> server : OK" || echo "  clientA -> server : FAIL"
  ip netns exec clientB ping -c1 -W1 10.0.0.10 >/dev/null && echo "  clientB -> server : OK" || echo "  clientB -> server : FAIL"
  ip netns exec clientA ping -c1 -W1 "${WAN_IP[routerB]}" >/dev/null && echo "  clientA -> routerB WAN : OK" || echo "  clientA -> routerB WAN : FAIL"

  if [ -f "$STUN_PID" ] && kill -0 "$(cat "$STUN_PID")" 2>/dev/null; then
    command -v stunclient >/dev/null 2>&1 || { echo "== STUN classification skipped (no stunclient; apt install stuntman) =="; exit 0; }
    echo "== STUN classification (server 10.0.0.10) =="
    for c in clientA clientB; do
      echo "[$c]"
      ip netns exec "$c" stunclient --mode full --localport 30000 10.0.0.10 2>&1 \
        | grep -Ei 'mapped address|nat behavior|nat filtering' | sed 's/^/  /' || echo "  (no response)"
    done
  else
    echo "== STUN classification skipped (start it: sudo $0 stun start) =="
  fi
}

# ---------------- convenience ----------------
cmd_stun() {
  need_root; up_and
  case "${1:-}" in
    start)
      command -v stunserver >/dev/null || err "stuntman not installed: apt install stuntman"
      [ -f "$STUN_PID" ] && kill -0 "$(cat "$STUN_PID")" 2>/dev/null && err "stunserver already running (pid $(cat "$STUN_PID"))"
      ip netns exec server stunserver --mode full \
        --primaryinterface 10.0.0.10 --altinterface 10.0.0.11 &
      echo $! > "$STUN_PID"; sleep 0.5
      if ! kill -0 "$(cat "$STUN_PID")" 2>/dev/null; then
        rm -f "$STUN_PID"
        err "stunserver failed to start; run manually to see why: ip netns exec server stunserver --mode full --primaryinterface 10.0.0.10 --altinterface 10.0.0.11"
      fi
      echo "stunserver up in 'server' ns (pid $(cat "$STUN_PID")) on 10.0.0.10:3478 (alt 10.0.0.11)"
      ;;
    stop)
      if [ -f "$STUN_PID" ]; then kill "$(cat "$STUN_PID")" 2>/dev/null || true; rm -f "$STUN_PID"; fi
      pkill -f 'stunserver --mode full' 2>/dev/null || true
      echo "stunserver stopped."
      ;;
    *) err "usage: $0 stun <start|stop>";;
  esac
}

cmd_run()   { need_root; up_and; [ $# -ge 2 ] || err "usage: $0 run <ns> <cmd...>"; ip netns exec "$@"; }
cmd_shell() { need_root; up_and; [ $# -ge 1 ] || err "usage: $0 shell <ns>"; ip netns exec "$1" "${SHELL:-/bin/bash}"; }

usage() {
cat <<EOF
natlab -- NAT hole-punching lab (1 public server + 2 clients behind separate NATs)

  up                     build topology (default NAT: $DEFAULT_TYPE on both)
  down                   destroy topology
  status                 namespaces, NAT types, live conntrack mappings
  nat A|B <type>         set NAT type for client A or B
  test                   reachability + STUN classification
  stun start|stop        run/stop the STUN server in the 'server' ns
  run <ns> <cmd...>      run a command inside a namespace
  shell <ns>             open a shell inside a namespace
  -v, --verbose          trace every command as it runs (file:line + function)

NAT types (and what they mean for UDP hole punching):
  none        no NAT; client is effectively public (baseline)
  fullcone    endpoint-independent mapping + filtering      -> punch always works
  restricted  EIM + addr/port-dependent filtering           -> punch works if BOTH sides punch
              (port-restricted cone -- the common home router)
  symmetric   addr/port-dependent mapping + filtering       -> STUN punch FAILS (need TURN)

namespaces / addresses:
  server   10.0.0.10 (+ alt 10.0.0.11)
  routerA  WAN 10.0.0.2 / LAN 192.168.1.1   clientA 192.168.1.100
  routerB  WAN 10.0.0.3 / LAN 192.168.2.1   clientB 192.168.2.100
EOF
}

# ---------------- dispatch ----------------
VERBOSE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; shift;;
    --) shift; break;;
    -h|--help) usage; exit 0;;
    -*) err "unknown option: $1 (try: $0 help)";;
    *) break;;
  esac
done
if [ "$VERBOSE" -eq 1 ]; then
  PS4='+ ${BASH_SOURCE[0]##*/}:${LINENO}: ${FUNCNAME[0]:-main}() '
  set -x
fi
[ $# -eq 0 ] && { usage; exit 0; }
sub=$1; shift || true
case "$sub" in
  up)                    cmd_up "$@";;
  down)                  cmd_down "$@";;
  status)                cmd_status "$@";;
  nat)                   cmd_nat "$@";;
  test)                  cmd_test "$@";;
  stun)                  cmd_stun "$@";;
  run)                   cmd_run "$@";;
  shell)                 cmd_shell "$@";;
  -h|--help|help)        usage;;
  *)                     err "unknown command '$sub' (try: $0 help)";;
esac

