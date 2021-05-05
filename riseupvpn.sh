#!/usr/bin/env bash
cd "$(realpath "$(dirname "${BASH_SOURCE[0]}")")" || exit 1
declare -g device="tunriseup$RANDOM"
declare -g pid_file=""
declare -g should_exit=0

# Function to notify user about missing dependencies
# and signals that exiting with failure is needed
_command() {
	IFS=''
	for x in "${@}"
	do
		if ! command -v "$x" &> /dev/null
		then
			echo "$x could not be found. Please install it." >&2
			declare -g should_exit=1
		fi
	done
}

# Function to clean-up on exit
on_exit() {
	set +u
	_jobs="$(cat "$pid_file" 2>/dev/null) $(jobs -p)"
	echo "* Killed all of the script's background processes"
	IFS=' '
	for x in $_jobs
	do
		kill -9 "$x" >/dev/null 2>&1
	done
	echo "* Removed residue files"
	rm -f -- "$management_sock" "$pid_file" 2>/dev/null
	declare -g pid_file=""
	declare -g management_sock=""
	resolvconf -d "$device" >/dev/null 2>&1
	echo
	set -u
}

# Requirements for this script
_command curl jq sed mktemp openvpn egrep netcat id kill openssl resolvconf

# Check if required user and group for openvpn are installed
if [ "$(getent passwd nobody)" = "" ]
then
	echo "You need to have nobody as a user" >&2
	declare -g should_exit=1
fi
if [ "$(getent group nobody)" != "" ]
then
	declare -g unprivgroup="nobody"
elif [ "$(getent group nogroup)" != "" ]
then
	declare -g unprivgroup="nogroup"
else
	echo "You need to have either nobody or nogroup as a group" >&2
	declare -g should_exit=1
fi

# Setup settings for the rest of the script
[ "$should_exit" = "1" ] && exit 1
unset should_exit
trap 'on_exit' EXIT
set -um

# Default RiseupVPN server settings
declare -g _riseupvpn="https://api.black.riseup.net"
declare -g _riseupvpn_gw="https://api.black.riseup.net:9001"
declare -g _riseupvpn_ca="https://black.riseup.net/provider.json"
declare -a -g _curl_std_opts_api=()
declare -a -g blacklist_locations
source riseupvpn.conf >/dev/null 2>&1
declare -g _curl_std_opts_api+=(--silent --fail "--capath" "/dev/null")
declare -g api_cert=""

# Get the API's certificate, I believe this is how it should be done
get_api_ca() {
	local x=0
	while :
	do
		IFS=$'\n'
		# shellcheck disable=SC2207
		ca_cert=( $(curl --silent "${_riseupvpn_ca}" | jq -cr '.ca_cert_uri+"\n"+.ca_cert_fingerprint'))
		api_cert="$(curl --silent "${ca_cert[0]}")"
		api_finger="$(echo "$api_cert" | openssl x509 -sha256 -fingerprint -noout | sed -e 's/://g' -e 's/ Fingerprint=/: /g')"
		if [ "${api_finger,,}" == "${ca_cert[1],,}" ]
		then
			echo "* Got API certificate and verfied"
			return 0
		else
			echo "* API certificate is invalid and verfication failed. Retrying"
			[ $x -ge 10 ] && exit 1
		fi
		x=$((x+1))
	done
}

# Create certificate and OVPN config for RiseupVPN
make_cert_and_cmdline() {
	if [ "$_riseupvpn_gw" != "none" ]
	then
		echo "* Getting list of closest VPN gateways"
		local riseupvpn_gw_sel
		riseupvpn_gw_list="$(curl "${_curl_std_opts_api[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn_gw/json")"
		# shellcheck disable=SC2207
		riseupvpn_gw_sel=( $(echo "$riseupvpn_gw_list" | jq -cr '.gateways[0:] | .[]') )
		unset riseupvpn_gw_list
	fi
	echo "* Getting new public and private certificate for the OpenVPN connection"
	riseupvpn_cert="$(curl "${_curl_std_opts_api[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn/3/cert" || curl "${_curl_std_opts_api[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn/1/cert")"
	declare -g riseupvpn_private_key riseupvpn_public_key
	riseupvpn_private_key="$(echo "$riseupvpn_cert" | sed -e '/-----BEGIN RSA PRIVATE KEY-----/,/-----END RSA PRIVATE KEY-----/!d')"
	riseupvpn_public_key="$(echo "$riseupvpn_cert" | sed -e '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/!d')"
	unset riseupvpn_cert

	declare -a -g make_opts=""
	echo "* Getting list of all VPN gateways, OpenVPN configuration and IP addresses"
	declare riseupvpn_gws
	riseupvpn_gws="$(curl "${_curl_std_opts_api[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn/3/config/eip-service.json" || curl "${_curl_std_opts_api[@]}" --cacert <(printf %s "$api_cert") "$_riseupvpn/1/config/eip-service.json")"
	# shellcheck disable=SC2207
	declare -a gw_len=( $(echo "$riseupvpn_gws" | jq -r '.gateways[] | .ip_address') )
	IFS=''
	for i in "${!gw_len[@]}"
	do
		set +u
		if [ -n "${riseupvpn_gw_sel[$i]}" ]
		then
			riseupvpn_gw_sel[$i]="$(echo "$riseupvpn_gws" | jq -cr  ".gateways[] | select(.host == \"${riseupvpn_gw_sel[$i]}\") | .ip_address")"
		fi
		set -u
		if [ -z "${riseupvpn_gw_sel[$i]}" ]
		then
			if [ "$_riseupvpn_gw" != "none" ]
			then
				echo "* List of closest servers failed. Picking server(s) at random."
			fi
			riseupvpn_gw_sel[$i]="$(echo "$riseupvpn_gws" | jq -cr  ".gateways[$i] | .ip_address")"
		fi
		local location
		location="$(echo "$riseupvpn_gws" | jq -cr ".gateways[] | select(.ip_address == \"${riseupvpn_gw_sel[$i]}\") | to_entries[] | select(.key== \"location\") | .value")"
		if [[ ! ${blacklist_locations[*]} =~ $location ]] || [[ -z $location ]]
		then
			local port proto
			port="$(echo "$riseupvpn_gws" | jq -cr  ".gateways[] | select(.ip_address == \"${riseupvpn_gw_sel[$i]}\") | to_entries[] | select(.key == \"capabilities\")| .value.transport | .[] | select(.type == \"openvpn\") | .ports[0]")"
			proto="$(echo "$riseupvpn_gws" | jq -cr  ".gateways[] | select(.ip_address == \"${riseupvpn_gw_sel[$i]}\") | to_entries[] | select(.key == \"capabilities\")| .value.transport | .[] | select(.type == \"openvpn\") | .protocols[0]")"
			case $proto in
					tcp) local proto="tcp-client" ;;
			esac
			declare -a -g make_opts+=("remote ${riseupvpn_gw_sel[$i]} $port $proto")
		fi
	done
	declare -g ovpn_config_file
	ovpn_config_file="$(echo "$riseupvpn_gws" | jq -rc '.openvpn_configuration | to_entries[] | "--\(.key) \"\(.value)\""')"
	IFS=$'\n' ovpn_config_file="$(echo "$ovpn_config_file" | sed -e '/ \"false\"$/d' -e 's/ \"true\"$//g' -e 's/ \"/ /g' -e 's/\"$//g' -e 's/^--//g')"
	ovpn_config_file="$(IFS=''; for x in "${!ovpn_config_file[@]}"; do echo "${ovpn_config_file[x]}"; done;)"
	ovpn_config_file="${ovpn_config_file} $(IFS=''; for x in "${!make_opts[@]}"; do echo "${make_opts[x]}"; done;)"
	unset riseupvpn_gws riseupvpn_gw_sel gw_len make_opts
}

# Start OpenVPN and monitoring sockets
openvpn_start() {
	IFS=''
	declare -g management_sock pid_file
	management_sock="$(mktemp -u)"
	pid_file="$(mktemp -u)"
	openvpn --daemon --config <(printf %s "$ovpn_config_file") --ca <(printf %s "$api_cert") \
		--cert <(printf %s "$riseupvpn_public_key") --key <(printf %s "$riseupvpn_private_key") \
		--remap-usr1 SIGTERM --client --nobind --management "$management_sock" unix --management-signal \
		--management-client-user "$(id -un)" --management-client-group "$(id -gn)" --dev "$device" \
		--tls-client --remote-cert-tls server --persist-key --persist-tun --persist-local-ip --auth-nocache \
		--user nobody --group "$unprivgroup" --writepid "$pid_file" --script-security 1 --verb 0 >/dev/null 2>&1
}

# Make sure the OpenVPN connection is alive and well
check_if_changes() {
	# shellcheck disable=SC2196
	while IFS= read -r line || [[ -n "$line" ]]
	do
		if echo "$line" | egrep -m 1 '^>STATE:.*,CONNECTED,' >/dev/null 2>&1
		then
			resolvconf -x -a "$device" <<-EOF
				nameserver 10.41.0.1
				nameserver 10.42.0.1
				search ~.
			EOF
		fi
		echo "$line" | egrep -m 1 '^>STATE:.*,RECONNECTING,' >/dev/null 2>&1 && break >/dev/null 2>&1
	done < <(echo 'state on' | netcat -U "$management_sock")
}

# Main function to call all other functions
main() {
	local y=1
	while :
	do
		echo "* Connection #$y"
		get_api_ca
		make_cert_and_cmdline
		openvpn_start >/dev/null 2>&1
		echo "* Started OpenVPN client"
		echo "* Monitoring OpenVPN status"
		check_if_changes
		echo "* Connection failed"
		echo "* Waiting 5 seconds after next reconnect..."
		sleep 5
		echo ""
		local y=$((y+1))
		on_exit
	done
}
main
