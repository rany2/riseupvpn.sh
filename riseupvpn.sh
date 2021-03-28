#!/usr/bin/env bash

cd "$(realpath $(dirname "${BASH_SOURCE[0]}"))"

declare -g pid_file=""
declare -g should_exit=0
declare -g keep_fw=""
declare -g keep_fw2=""
declare -g keep_fw3=""

# https://stackoverflow.com/a/26966800
kill_descendant_processes() {
	local pid="$1"
	local and_self="${2:-false}"
	if children="$(pgrep -P "$pid")"; then
		for child in $children; do
			kill_descendant_processes "$child" true
		done
	fi
	if [[ "$and_self" == true ]]; then
		kill -9 "$pid"
	fi
}

_command() {
	IFS=''
	for x in ${@}; do
		if ! command -v $x &> /dev/null; then
			echo "$x could not be found. Please install it." >&2
			declare -g should_exit=1
		fi
	done
}

on_exit() {
	set +u
	local _jobs="$(jobs -p) $(cat "$pid_file" 2>/dev/null)"
	echo "* Killed all of the script's background processes"
	if [ -n "$_jobs" ]; then
		IFS=' '
		for x in $_jobs; do
			kill_descendant_processes $x true >/dev/null 2>&1
		done
	fi
	echo "* Removed residue files"
	rm -f -- "$management_sock" "$pid_file" 2>/dev/null
	declare -g pid_file=""
	declare -g management_sock=""
	if [ "$1" != "nofwstop" ]; then
		fw_stop >/dev/null 2>&1
	fi
	echo ""
	set -u
}

_command curl jq sed umask mktemp tee openvpn sh grep netcat id awk ip iptables ip6tables cut pgrep kill conntrack openssl

[ "$should_exit" = "1" ] && exit 1
unset should_exit

# Check if required user and group for openvpn are installed
if [ "$(getent passwd nobody)" = "" ];then
	echo "You need to have nobody as a user" >&2
	declare -g should_exit=1
fi
if [ "$(getent group nobody)" != "" ];then
	declare -g unprivgroup="nobody"
elif [ "$(getent group nogroup)" != "" ];then
	declare -g unprivgroup="nogroup"
else
	echo "You need to have either nobody or nogroup as a group" >&2
	declare -g should_exit=1
fi
[ "$should_exit" = "1" ] && exit 1
unset should_exit

trap 'on_exit' EXIT

set -um

declare -g _riseupvpn="https://api.black.riseup.net"
declare -g _riseupvpn_gw="https://api.black.riseup.net:9001"
declare -g _riseupvpn_ca="https://black.riseup.net/provider.json"
declare -a -g _curl_std_opts_api=()
declare -a -g blacklist_locations
source riseupvpn.config >/dev/null 2>&1
declare -g _curl_std_opts_api+=(--silent --fail "--capath" "/dev/null")
declare -a -g _curl_fw_ip=()
declare -g api_cert=""

get_api_ca() {
	local x=0; while :; do
		local _curl_fw_ip=("--connect-to" "$(echo "$_riseupvpn_ca" | awk -F[/:] '{print $4}')::$keep_fw3:")
		IFS=$'\n'
		local ca_cert=( $(curl --silent "${_curl_fw_ip[@]}" "${_riseupvpn_ca}" | jq -cr '.ca_cert_uri+"\n"+.ca_cert_fingerprint'))
		declare -g api_cert="$(curl --silent "${_curl_fw_ip[@]}" "${ca_cert[0]}")"
		local api_finger="$(echo "$api_cert" | openssl x509 -sha256 -fingerprint -noout | sed -e 's/://g' -e 's/ Fingerprint=/: /g')"
		if [ "${api_finger,,}" == "${ca_cert[1],,}" ]; then
			echo "* Got API certificate and verfied";
			return 0
		else
			echo "* API certificate is invalid and verfication failed. Retrying"
			[ $x -ge 10 ] && exit 1
		fi
		local x=$((x+1))
	done
}

make_cert_and_cmdline() {
	[ -n "$keep_fw" ] && local _curl_fw_ip=("--connect-to" "$(echo "$_riseupvpn" | awk -F[/:] '{print $4}')::$keep_fw:")
	if [ "$_riseupvpn_gw" != "none" ];then
		[ -n "$keep_fw2" ] && local _curl_fw_ip+=("--connect-to" "$(echo "$_riseupvpn_gw" | awk -F[/:] '{print $4}')::$keep_fw2:")
		echo "* Getting list of closest VPN gateways"
		local riseupvpn_gw_list="$(curl "${_curl_std_opts_api[@]}" "${_curl_fw_ip[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn_gw/json")"
		local -a riseupvpn_gw_sel=( $(echo "$riseupvpn_gw_list" | jq -cr '.gateways[0:] | .[]') )
		unset riseupvpn_gw_list
	fi
	echo "* Getting new public and private certificate for the OpenVPN connection"
	local riseupvpn_cert="$(curl "${_curl_std_opts_api[@]}" "${_curl_fw_ip[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn/3/cert" || curl "${_curl_std_opts_api[@]}" "${_curl_fw_ip[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn/1/cert")"
	declare -g riseupvpn_private_key="$(echo "$riseupvpn_cert" | sed -e '/-----BEGIN RSA PRIVATE KEY-----/,/-----END RSA PRIVATE KEY-----/!d')"
	declare -g riseupvpn_public_key="$(echo "$riseupvpn_cert" | sed -e '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/!d')"
	unset riseupvpn_cert

	declare -a -g make_opts=""
	declare -a -g firewall=""
	echo "* Getting list of all VPN gateways, OpenVPN configuration and IP addresses"
	declare riseupvpn_gws="$(curl "${_curl_std_opts_api[@]}" "${_curl_fw_ip[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn/3/config/eip-service.json" || curl "${_curl_std_opts_api[@]}" "${_curl_fw_ip[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn/1/config/eip-service.json")"
	declare -a gw_len=( $(echo "$riseupvpn_gws" | jq -r '.gateways[] | .ip_address') )
	IFS=''; for i in ${!gw_len[@]}; do
		set +u
		[ -n "$riseupvpn_gw_sel[$i]" ] && local riseupvpn_gw_sel[$i]="$(echo "$riseupvpn_gws" | jq -cr  ".gateways[] | select(.host == \"${riseupvpn_gw_sel[$i]}\") | .ip_address")"
		set -u
		if [ -z "${riseupvpn_gw_sel[$i]}" ]; then
			if [ "$_riseupvpn_gw" != "none" ];then
				echo "* List of closest servers failed. Picking server(s) at random."
			fi
			local riseupvpn_gw_sel[$i]="$(echo "$riseupvpn_gws" | jq -cr  ".gateways[$i] | .ip_address")"
		fi
		local location="$(echo "$riseupvpn_gws" | jq -cr ".gateways[] | select(.ip_address == \"${riseupvpn_gw_sel[$i]}\") | to_entries[] | select(.key== \"location\") | .value")"
		if [[ ! ${blacklist_locations[*]} =~ $location ]] || [[ -z $location ]]; then
			local port="$(echo "$riseupvpn_gws" | jq -cr  ".gateways[] | select(.ip_address == \"${riseupvpn_gw_sel[$i]}\") | to_entries[] | select(.key == \"capabilities\")| .value.transport | .[] | select(.type == \"openvpn\") | .ports[0]")"
			local proto="$(echo "$riseupvpn_gws" | jq -cr  ".gateways[] | select(.ip_address == \"${riseupvpn_gw_sel[$i]}\") | to_entries[] | select(.key == \"capabilities\")| .value.transport | .[] | select(.type == \"openvpn\") | .protocols[0]")"
			declare -g firewall[i]="${riseupvpn_gw_sel[$i]} $port $proto"
			case $proto in
					tcp) local proto="tcp-client" ;;
			esac
			declare -a -g make_opts+=("remote ${riseupvpn_gw_sel[$i]} $port $proto")
		fi
	done
	declare -g ovpn_config_file="$(echo "$riseupvpn_gws" | jq -rc '.openvpn_configuration | to_entries[] | "--\(.key) \"\(.value)\""')"
	IFS=$'\n' declare -a -g ovpn_config_file=( $(echo "$ovpn_config_file" | sed -e '/ \"false\"$/d' -e 's/ \"true\"$//g' -e 's/ \"/ /g' -e 's/\"$//g' -e 's/^--//g') )
	declare -g ovpn_config_file="$(IFS=''; for x in ${!ovpn_config_file[@]}; do echo ${ovpn_config_file[x]}; done;)"
	declare -g ovpn_config_file+="$(IFS=''; for x in ${!make_opts[@]}; do echo ${make_opts[x]}; done;)"
	unset riseupvpn_gws riseupvpn_gw_sel gw_len make_opts
}

keep_fw_onreconnect() {
	local x=0; while [ -z "$keep_fw" ] || [ -z "$keep_fw2" ] || [ -z "$keep_fw3" ]; do
		[ "$x" == "0" ] && echo "* Getting API IP addresses for reconnect" && local x=1
		sleep 0.1
		declare -g keep_fw="$(getent ahostsv4 "$(echo "$_riseupvpn" | awk -F[/:] '{print $4}')" | grep STREAM | head -n 1 | cut -d ' ' -f 1)"
		if [ "$_riseupvpn_gw" != "none" ];then
			declare -g keep_fw2="$(getent ahostsv4 "$(echo "$_riseupvpn_gw" | awk -F[/:] '{print $4}')" | grep STREAM | head -n 1 | cut -d ' ' -f 1)"
		else
			declare -g keep_fw2=none
		fi
		declare -g keep_fw3="$(getent ahostsv4 "$(echo "$_riseupvpn_ca" | awk -F[/:] '{print $4}')" | grep STREAM | head -n 1 | cut -d ' ' -f 1)"
	done
	[ "$x" == "1" ] && echo "* Got API IP addresses for reconnect"
	fw_start >/dev/null 2>&1
}

openvpn_start() {
	IFS=''
	declare -g management_sock="$(mktemp -u)"
	declare -g pid_file="$(mktemp -u)"
	openvpn --daemon --config <(printf %s "$ovpn_config_file") --ca <(printf %s "$api_cert") \
		--cert <(printf %s "$riseupvpn_public_key") --key <(printf %s "$riseupvpn_private_key") \
		--remap-usr1 SIGTERM --client --nobind --management $management_sock unix --management-signal \
		--management-client-user "$(id -un)" --management-client-group "$(id -gn)" --dev tunriseupvpn \
		--tls-client --remote-cert-tls server --persist-key --persist-tun --persist-local-ip --auth-nocache \
		--user nobody --group "$unprivgroup" --writepid "$pid_file" --script-security 1 --verb 0 >/dev/null 2>&1
}

check_if_changes() {
	while IFS= read -r line || [[ -n "$line" ]]; do
		echo "$line" | grep -E -m 1 '^>STATE:.*,CONNECTED,SUCCESS,' >/dev/null 2>&1 && conntrack --flush >/dev/null 2>&1
		echo "$line" | grep -E -m 1 '^>STATE:.*,RECONNECTING,'      >/dev/null 2>&1 && break             >/dev/null 2>&1
	done < <(echo -e 'state on' | netcat -U "$management_sock")
}

fw_start() {
	IFS=' '

	iptables  --new-chain riseupvpn-bash
	ip6tables --new-chain riseupvpn-bash

	iptables  -t nat --new-chain riseupvpn-bashnat
	ip6tables -t nat --new-chain riseupvpn-bashnat

	iptables  -t nat --new-chain riseupvpn-bashpost
	ip6tables -t nat --new-chain riseupvpn-bashpost

	# Add riseupvpn-bash to OUTPUT
	iptables  -C OUTPUT --jump riseupvpn-bash || iptables  -I OUTPUT --jump riseupvpn-bash
	ip6tables -C OUTPUT --jump riseupvpn-bash || ip6tables -I OUTPUT --jump riseupvpn-bash

	# Add riseupvpn-bashnat to OUTPUT nat
	iptables   -t nat -C OUTPUT --jump riseupvpn-bashnat || iptables  -t nat -I OUTPUT --jump riseupvpn-bashnat
	ip6tables  -t nat -C OUTPUT --jump riseupvpn-bashnat || ip6tables -t nat -I OUTPUT --jump riseupvpn-bashnat

	# Add riseupvpn-bashnat to OUTPUT nat
	iptables   -t nat -C POSTROUTING --jump riseupvpn-bashpost || iptables  -t nat -I POSTROUTING --jump riseupvpn-bashpost
	ip6tables  -t nat -C POSTROUTING --jump riseupvpn-bashpost || ip6tables -t nat -I POSTROUTING --jump riseupvpn-bashpost

	# Reject all before doing rule below
	iptables  -I OUTPUT -j REJECT
	ip6tables -I OUTPUT -j REJECT

	# Flush all OUTPUT reject
	iptables  -F riseupvpn-bash
	ip6tables -F riseupvpn-bash

	# Flush all nat and postrouting
	iptables  -t nat -F riseupvpn-bashnat
	ip6tables -t nat -F riseupvpn-bashnat
	iptables  -t nat -F riseupvpn-bashpost
	ip6tables -t nat -F riseupvpn-bashpost

	# Reject all from all
	iptables  -I riseupvpn-bash -j REJECT
	ip6tables -I riseupvpn-bash -j REJECT

	# Remove OUTPUT Rejection
	iptables  -D OUTPUT 1
	ip6tables -D OUTPUT 1

	# Block all from RiseupVPN tun
	iptables  -I riseupvpn-bash -o tunriseupvpn -j REJECT
	ip6tables -I riseupvpn-bash -o tunriseupvpn -j REJECT

	# Block all IPv4 Internet from non-RiseupVPN
	local internet="0.0.0.0/5 8.0.0.0/7 11.0.0.0/8 12.0.0.0/6 16.0.0.0/4 32.0.0.0/3 64.0.0.0/2 128.0.0.0/3 160.0.0.0/5 168.0.0.0/6 172.0.0.0/12 172.32.0.0/11 172.64.0.0/10 172.128.0.0/9 173.0.0.0/8 174.0.0.0/7 176.0.0.0/4 192.0.0.0/9 192.128.0.0/11 192.160.0.0/13 192.169.0.0/16 192.170.0.0/15 192.172.0.0/14 192.176.0.0/12 192.192.0.0/10 193.0.0.0/8 194.0.0.0/7 196.0.0.0/6 200.0.0.0/5 208.0.0.0/4"
	for x in $internet;do
		iptables  -I riseupvpn-bash -d $x -j REJECT
	done

	# Block all IPv6 internet from non-RiseupVPN
	local internet6="2000::/3"
	for x in $internet6; do
		ip6tables -I riseupvpn-bash -d $x -j REJECT
	done

	# Allow loopback interface
	iptables  -I riseupvpn-bash -o lo+ -d 127.0.0.0/8   -j ACCEPT
	ip6tables -I riseupvpn-bash -o lo+ -d       ::1/128 -j ACCEPT

	# Allow RiseupVPN API addresses and DNS
	local z=0
	[ -n "$keep_fw"  ] && iptables -I riseupvpn-bash -d ${keep_fw} -j ACCEPT && local z=1
	[ -n "$keep_fw2" ] && [ "$keep_fw2" != "none" ] && iptables -I riseupvpn-bash -d ${keep_fw2} -j ACCEPT
	[ -n "$keep_fw3" ] && iptables -I riseupvpn-bash -d ${keep_fw3} -j ACCEPT
	if [ "$z" = "1" ];then
		iptables  -t nat -I riseupvpn-bashnat -p udp --dport 53 -j DNAT --to 10.41.0.1:53
		iptables  -t nat -I riseupvpn-bashnat -p tcp --dport 53 -j DNAT --to 10.41.0.1:53
		iptables  -t nat -I riseupvpn-bashnat -p udp -o lo+ --dest 127.0.0.0/8 --dport 53 -j ACCEPT
		iptables  -t nat -I riseupvpn-bashnat -p tcp -o lo+ --dest 127.0.0.0/8 --dport 53 -j ACCEPT
		iptables  -t nat -I riseupvpn-bashpost -p udp -o tunriseupvpn --dest 10.41.0.1 --dport 53 --jump MASQUERADE
		iptables  -t nat -I riseupvpn-bashpost -p tcp -o tunriseupvpn --dest 10.41.0.1 --dport 53 --jump MASQUERADE
		iptables  -I riseupvpn-bash -p tcp --dport 53 -j ACCEPT
		iptables  -I riseupvpn-bash -p udp --dport 53 -j ACCEPT
		ip6tables -I riseupvpn-bash -p tcp --dport 53 -j REJECT
		ip6tables -I riseupvpn-bash -p udp --dport 53 -j REJECT
	else
		for x in '' 6; do
			ip${x}tables -I riseupvpn-bash -p tcp --dport 53 -j ACCEPT
			ip${x}tables -I riseupvpn-bash -p udp --dport 53 -j ACCEPT
		done
	fi

	# Allow only IPv4 Internet to go through RiseupVPN
	for x in $internet;do
		iptables  -I riseupvpn-bash -d $x -o tunriseupvpn -j ACCEPT
	done

	# Allow only IPv6 Internet to go through RiseupVPN
	for x in $internet6;do
		ip6tables -I riseupvpn-bash -d $x -o tunriseupvpn -j ACCEPT
	done

	# Allow the current ranges (incase we have a public IP)
	local routes=( $(ip route list | grep '\bproto kernel\b' | cut -d' ' -f1) )
	local ifs=( $(ip route list | grep '\bproto kernel\b' | cut -d' ' -f3) )
	for i in ${!routes[@]}; do
		iptables  -I riseupvpn-bash -d ${routes[$i]} -o ${ifs[$i]} -j ACCEPT
	done
	local routes6=( $(ip -6 route list | grep '\bproto kernel\b' | cut -d' ' -f1) )
	local ifs6=( $(ip -6 route list | grep '\bproto kernel\b' | cut -d' ' -f3) )
	for i in ${!routes6[@]}; do
		ip6tables -I riseupvpn-bash -d ${routes6[$i]} -o ${ifs6[$i]} -j ACCEPT
	done

	# Excempt the RiseupVPN IPs
	for i in ${!firewall[@]}; do
		local fw_ip="$(echo ${firewall[$i]} | cut -d ' ' -f1)"
		local fw_port="$(echo ${firewall[$i]} | cut -d ' ' -f2)"
		local fw_proto="$(echo ${firewall[$i]} | cut -d ' ' -f3)"
		iptables -I riseupvpn-bash -p $fw_proto -d $fw_ip --dport $fw_port -j ACCEPT
	done

	# Now we can delete REJECT all
	iptables  -D riseupvpn-bash -j REJECT
	ip6tables -D riseupvpn-bash -j REJECT

	# Reset connection
	conntrack --flush
}

fw_stop() {
	iptables  --flush riseupvpn-bash
	ip6tables --flush riseupvpn-bash

	iptables  --delete OUTPUT --jump riseupvpn-bash
	ip6tables --delete OUTPUT --jump riseupvpn-bash

	iptables  --delete-chain riseupvpn-bash
	ip6tables --delete-chain riseupvpn-bash

	iptables  -t nat --flush riseupvpn-bashnat
	ip6tables -t nat --flush riseupvpn-bashnat

	iptables  -t nat --delete OUTPUT --jump riseupvpn-bashnat
	ip6tables -t nat --delete OUTPUT --jump riseupvpn-bashnat

	iptables  -t nat --delete-chain riseupvpn-bashnat
	ip6tables -t nat --delete-chain riseupvpn-bashnat

	iptables  -t nat --flush riseupvpn-bashpost
	ip6tables -t nat --flush riseupvpn-bashpost

	iptables  -t nat --delete POSTROUTING --jump riseupvpn-bashpost
	ip6tables -t nat --delete POSTROUTING --jump riseupvpn-bashpost

	iptables  -t nat --delete-chain riseupvpn-bashpost
	ip6tables -t nat --delete-chain riseupvpn-bashpost

	conntrack --flush
}

main() {
	local y=1;while :; do
		echo "* Connection #$y"
		keep_fw_onreconnect >/dev/null 2>&1
		get_api_ca
		make_cert_and_cmdline
		keep_fw_onreconnect >/dev/null 2>&1
		openvpn_start >/dev/null 2>&1
		keep_fw_onreconnect >/dev/null 2>&1
		echo "* Started OpenVPN client"
		echo "* Monitoring OpenVPN status"
		check_if_changes
		echo "* Connection failed"
		echo "* Waiting 5 seconds after next reconnect..."
		sleep 5
		echo ""
		local y=$(($y+1))
		on_exit nofwstop
	done
}; main

