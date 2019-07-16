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

# Set up a two network namespaces bridged with a veth device,
# with v4 subnet 192.168.1.0/24 and v6 subnet fd::/64.

set -eu

readonly NSPREFIX=$1
readonly NS1="${NSPREFIX}1"
readonly NS2="${NSPREFIX}2"
shift

usage() {
	echo "usage: $0 <ns prefix> <cmd>" 1>&2
	exit 1
}

cleanup() {
	set +e
	ip netns del "${NS2}"
	ip netns del "${NS1}"
}

if [[ "$#" -lt 2 ]]; then
	usage "$@"
fi

ip netns add "${NS1}"
ip netns add "${NS2}"

trap cleanup EXIT

# Bring loopback up
ip -netns "${NS1}" link set lo up
ip -netns "${NS2}" link set lo up

# Bridge the two namespaces with a veth device.
ip link add veth1 mtu 1500 netns "${NS1}" type veth \
  peer name veth2 mtu 1500 netns "${NS2}"

# Bring the devices up
ip -netns "${NS1}" link set veth1 up
ip -netns "${NS2}" link set veth2 up

# Set fixed MAC addresses on the devices
ip -netns "${NS1}" link set dev veth1 address 02:02:02:02:02:02
ip -netns "${NS2}" link set dev veth2 address 06:06:06:06:06:06

# Add IP addresses to the devices
ip -netns "${NS1}" addr add 192.168.1.1/24 dev veth1
ip -netns "${NS2}" addr add 192.168.1.2/24 dev veth2
ip -netns "${NS1}" addr add       fd::1/64 dev veth1 nodad
ip -netns "${NS2}" addr add       fd::2/64 dev veth2 nodad

# Wait for fully configured and link up
sleep 0.2

$@
