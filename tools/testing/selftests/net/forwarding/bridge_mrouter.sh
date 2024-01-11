#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Interface naming convention:
#
# Prefix:
# - (i)nput:   Where packets are injected
# - (o)utput:  Non-router reference port
# - (q)uerier: Where queries are generated/injected
# - (r)outer:  Port under test
#
# Suffix:
# - (b)ridge:  The side of a looped pair that is attached to the bridge
# - (h)ost:    Host side of a looped pair, where the other end is
#              attached to the bridge

ALL_TESTS="mrouter_test"
NUM_NETIFS=6
MODE=${MODE:-port}
#STRICT=

source lib.sh

ip4_grp()
{
    printf 239.255.0.$1
}

ip6_grp()
{
    printf ff02::ff0$1
}

mac_grp()
{
    printf 01:00:00:00:00:0$1
}

register_grp()
{
    local permanent=$([ $1 = br0 ] || echo permanent)

    bridge mdb add dev br0 port $1 grp $(mac_grp $2)  permanent
    bridge mdb add dev br0 port $1 grp $(ip4_grp $2) $permanent
    bridge mdb add dev br0 port $1 grp $(ip6_grp $2) $permanent
}

unregister_grp()
{
    bridge mdb del dev br0 port $1 grp $(ip6_grp $2)
    bridge mdb del dev br0 port $1 grp $(ip4_grp $2)
    bridge mdb del dev br0 port $1 grp $(mac_grp $2)
}

mcast_set()
{
	local port=$1
	local flood=$2
	local mrouter=$3

	case $mrouter in
	permanent)
		mrouter=2
		;;
	off)
		mrouter=0
		;;
	esac

	if [ $port = br0 ]; then
		flood=$([ $flood = on ] && echo 1 || echo 0)

		ip link set dev br0 type bridge \
			mcast_flood $flood mcast_router $mrouter
	else
		bridge link set dev $port \
		       mcast_flood $flood mcast_router $mrouter
	fi
}

br_mdb_find()
{
	local selector=$1

	bridge -d -j mdb show dev br0 | \
		jq -e ".[][\"mdb\"][] | select($selector)"
}

br_mdb_any()
{
	local selector=$1
	br_mdb_find "$selector" &>/dev/null && echo yes
}

verify_port()
{
	local h=$1
	local b=$2
	local proto=$3
	local router=
	local flood=
	local grp=
	local registered=
	local member=
	local rx=
	local dbg=

	if [ $b = br0 ]; then
		[ $(linkinfo_get br0 mcast_router) = 2 ] && router=yes
	else
		[ $(linkinfo_upper_get $b multicast_router) = 2 ] && router=yes
		[ $(linkinfo_upper_get $b mcast_flood) = true ] && flood=yes
	fi

	if [ "$DEBUG" ]; then
		dbg=$(printf "  h:$h b:$b proto:$proto router:%-3s flood:%-3s" \
			     $([ "$router" ] && echo yes || echo no) \
			     $([ "$flood" ] && echo yes || echo no))
		log_info "$dbg"
	fi

	for g in 1 2 3; do
		case $proto in
		mac)
			grp=$(mac_grp $g)
			;;
		ip4)
			grp=$(ip4_grp $g)
			;;
		ip6)
			grp=$(ip6_grp $g)
			;;
		esac

		registered=$(br_mdb_any ".grp == \"$grp\"")
		member=$(br_mdb_any ".grp == \"$grp\" and .port == \"$b\"")

		tcpdump_show $h | grep -q "> $grp"
		rxerr=$?

		if [ "$DEBUG" ]; then
			dbg=$(printf "    g:$g registered:%-3s member:%-3s rx:%-3s" \
				     $([ "$registered" ] && echo yes || echo no) \
				     $([ "$member" ] && echo yes || echo no) \
				     $([ $rxerr -eq 0 ] && echo yes || echo no))
			log_info "$dbg"
		fi

		# First, verify that we receive everything that is
		# nonnegotiable:
		#
		# - All groups the port is a member of
		# - Unregistered MAC multicast if port has mcast_flood set
		# - All IP groups if port is a router
		#
		if [ "$member" ]; then
			check_err $rxerr "Expected $grp on $h, since $b is a member"
			[ $rxerr -eq 0 ] && continue
		elif [ "$proto" = mac ] && [ -z "$registered" -a "$flood" ]; then
			check_err $rxerr "Expected ${grp} on $h, since $b floods multicast"
			[ $rxerr -eq 0 ] && continue
		elif [ "$proto" != mac ] && [ "$router" ]; then
			check_err $rxerr "Expected $grp on $h, since $b is a router port"
			[ $rxerr -eq 0 ] && continue
		fi

		# Nothing more is expected, so if the current group was not
		# received, then we are done.
		[ $rxerr -ne 0 ] && continue

		# We received something we did not expect. This can
		# happen because the underlying hardware is not able to
		# separately control flooding of IP and non-IP
		# multicast; which is why we can optionally use a less
		# strict enforcement policy...
		if [ "$STRICT" ]; then
			check_err 1 "Unexpected $grp on $h"
			continue
		fi

		# ...in which we allow unexpected MAC multicast on
		# router ports, and conversely unexpected IP multicast
		# on ports with flooding enabled.
		case $proto in
		mac)
			[ "$router" ]
			check_err $? "Unexpected $grp on $h, since $b is not a router port"
			;;
		ip*)
			[ "$flood" ]
			check_err $? "Unexpected $grp on $h, since $b does not flood multicast"
			;;
		esac
	done
}

verify()
{
	tcpdump_start $oh
	tcpdump_start $rh

	sleep 2
	# Inject multicast to all group+protocol combinations
	for g in 1 2 3; do
		$MZ $ih -q    -a own -b $(mac_grp $g)
		$MZ $ih -q    -t udp -B $(ip4_grp $g)
		$MZ $ih -q -6 -t udp -B $(ip6_grp $g)
	done
	sleep 2

	tcpdump_stop $oh
	tcpdump_stop $rh

	for proto in mac ip4 ip6; do
		verify_port $oh $ob $proto
		verify_port $rh $rb $proto
	done
}

mrouter_test()
{
	# Both groups that where known before a port is marked as a
	# multicast router port and those that are registered
	# afterwards should be forwarded to the router.
	RET=0
	register_grp $ob 1
	mcast_set $rb off permanent
	register_grp $ob 2
	verify
	log_test "Registered groups are received"

	# When a group reverts to being unregistered, routers should
	# still receive it.
	RET=0
	unregister_grp $ob 1
	verify
	log_test "Previously registered group is still received"

	# Registering groups on a router port should not have any effect
	RET=0
	unregister_grp $ob 2
	register_grp $rb 1
	register_grp $rb 2
	verify
	log_test "Registered groups, on a router port, are received"

	# Groups registered on the router port should still be received
	# when disabling multicast router.
	RET=0
	mcast_set $rb off off
	verify
	log_test "Registered groups, on a former router port, are received"

	# Enabling multicast flooding should not affect forwarding of
	# registered groups.
	RET=0
	mcast_set $ob on off
	verify
	log_test "Flooding does not affect registered groups"
}

setup_prepare()
{
	local b1=${NETIFS[p1]}
	local h1=${NETIFS[p2]}
	local b2=${NETIFS[p3]}
	local h2=${NETIFS[p4]}
	local b3=${NETIFS[p5]}
	local h3=${NETIFS[p6]}

	ib=$b1
	ih=$h1
	ob=$b2
	oh=$h2

	case $MODE in
	port)
		qb=br0
		rb=$b3
		rh=$h3
		;;
	host)
		qb=$b3
		qh=$h3
		rb=br0
		rh=br0
		;;
	esac

	vrf_prepare

	ip link add dev br0 up type bridge \
		mcast_snooping 1 \
		mcast_query_interval 100 \
		mcast_startup_query_interval 100 \
		mcast_query_response_interval 100

	for bport in $b1 $b2 $b3; do
		ip link set dev $bport up master br0
	done

	simple_if_init $h1 192.168.255.1/24 2001::ffff:1/64
	simple_if_init $h2 192.168.255.2/24 2001::ffff:2/64
	simple_if_init $h3 192.168.255.3/24 2001::ffff:3/64
	simple_if_init br0 192.168.255.9/24 2001::ffff:9/64

	mcast_set $ob off 0
	mcast_set $rb off 0

	case $MODE in
	port)
		ip link set dev br0 type bridge mcast_querier 1
		;;
	host)
		echo TODO start querier transmission on $qh
		;;
	esac
}

cleanup()
{
	pre_cleanup

	for iface in br0 $h3 $h2 $h1; do
		simple_if_fini $iface
	done

	tcpdump_cleanup $oh
	tcpdump_cleanup $rh

	ip link del dev br0

	vrf_cleanup
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
