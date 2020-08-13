#!/bin/bash
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

nsprefix=icept
ns1="${nsprefix}1"
ns2="${nsprefix}2"

cfg_cgroup_root=
cfg_cgroup_ns1=
cfg_cgroup_ns2=

cfg_mark=1337
cfg_port_intercept=8000
cfg_port_server=9000

set -e

cleanup() {
	set +e

	kill $(jobs -p) 2>/dev/null

	if [[ -d "${cfg_cgroup_ns2}" ]]; then
		rmdir "${cfg_cgroup_ns2}"
		rmdir "${cfg_cgroup_ns1}"
	fi
	mountpoint -q "${cfg_cgroup_root}" && umount "${cfg_cgroup_root}"
	if [[ -d "${cfg_cgroup_root}" ]]; then
		rmdir "${cfg_cgroup_root}"
	fi
}

setup() {
	cfg_cgroup_root=$(mktemp -d)
	mount -t cgroup2 none "${cfg_cgroup_root}"
	cfg_cgroup_ns1="$(mktemp -d ${cfg_cgroup_root}/icept_XXXX_${ns1})"
	cfg_cgroup_ns2="$(mktemp -d ${cfg_cgroup_root}/icept_XXXX_${ns2})"
}

in_cgroup() {
	local -r cgroup=$1
	shift

	(echo $BASHPID > "${cgroup}/cgroup.procs"; $@)
}

do_intercept() {
	local -r ns=$1
	local -r ipt_bin=$2
	local -r family=$3
	local -r mode=$4
	local -r cgroup=$5

	# cannot pass extra arg "", so combine with role arg
	if [[ "${mode}" == "sockmap" ]]; then
		local -r cfg_role_arg="-s intercept"
	elif [[ "${mode}" == "skmsg" ]]; then
		local -r cfg_role_arg="-s intercept -C ${cgroup}"
	else
		local -r cfg_role_arg="intercept"
	fi

	ip netns exec "${ns}" ./icept "-${family}" \
					-L "${cfg_port_intercept}" \
					-m "${cfg_mark}" \
					${cfg_role_arg} &

	# Filtering on mark is unsafe, as client can set mark to bypass.
	# Should use -m owner --uid-owner '!' "${ICEPT_PID}"
	# But let's not mess with user accounts in this test environment,
	# so that the test can be run as non-root.
	for hook in OUTPUT PREROUTING; do
		ip netns exec "${ns}" \
			${ipt_bin} -t nat -A "${hook}" -p tcp \
				   -m mark '!' --mark "${cfg_mark}" \
				   -j REDIRECT --to-ports "${cfg_port_intercept}"
	done
}

do_main() {
	local -r ipt_bin=$1
	local -r cfg_family=$2
	local -r cfg_addr_server=$3
	local -r cfg_do_icept=$4

	echo -e "\nTest IPv${cfg_family}\n"

	# Start server
	in_cgroup "${cfg_cgroup_ns2}" \
		ip netns exec "${ns2}" ./icept "-${cfg_family}" \
					-L "${cfg_port_server}" \
					server &

	# Start intercept service (optionally)
	if [[ "${cfg_do_icept}" != "" ]]; then
		do_intercept "${ns1}" "${ipt_bin}" "${cfg_family}" "${cfg_do_icept}" "${cfg_cgroup_ns1}"
		sleep 0.2
		do_intercept "${ns2}" "${ipt_bin}" "${cfg_family}" "${cfg_do_icept}" "${cfg_cgroup_ns2}"
	fi

	# Wait for servers to be up
	sleep 0.2

	# Start client
	in_cgroup "${cfg_cgroup_ns1}" \
		ip netns exec "${ns1}" ./icept "-${cfg_family}" \
					-d "${cfg_addr_server}" \
					-D "${cfg_port_server}" \
					client

	# Wait for servers to be down
	sleep 0.2

	echo -e "\nTest IPv${cfg_family}: OK\n"
}

# Args: no args: restart, in netns
if [[ "$#" -eq 0 ]]; then
	./with_veth.sh icept $0 __subprocess
	exit $?
fi

# Args: too many: fail
if [[ "$#" -gt 1 || "$1" != "__subprocess" ]]; then
	echo "usage: $0" 1>&2
	exit 1
fi

trap cleanup EXIT

setup

echo "Test Direct"
do_main ip6tables 6 "fd::2" ""
do_main iptables 4 "192.168.1.2" ""

echo "Test Intercept (iptables)"
do_main ip6tables 6 "fd::2" iptables
do_main iptables 4 "192.168.1.2" iptables

echo "Test Intercept (sockmap)"
do_main ip6tables 6 "fd::2" sockmap
do_main iptables 4 "192.168.1.2" sockmap

echo "Test Intercept (skmsg)"
do_main ip6tables 6 "fd::2" skmsg
cleanup
set -e
setup
do_main iptables 4 "192.168.1.2" skmsg

echo "OK. All passed"
