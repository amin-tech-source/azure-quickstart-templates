#!/bin/bash

nginxUserName=$1
nginxNumberOfWorkProcesses=$2
gitHostName=$3
gitGroupName=$4
gitRepoName=$5
gitSshPrivateKey=$6

# git@gitHostName:gitGroupName/gitRepoName.git
OUTPUTFILE="/tmp/`basename $0`.log"

GITBASEDIR=/opt/gitwork
GITBASEDIRCURREPO=${GITBASEDIR}/group__${gitGroupName}/${gitRepoName}
SSHBASEDIR=/root/.ssh
TMPFILEKEY=/tmp/tmp_key

IP_LOADBALANCER="13.80.20.174"

SERVER_NAME=$( uname -n )
SERVER_IP=$(ip route get 8.8.8.8 | awk '/8.8.8.8/ {print $NF}')

# Public key's array to set into 'authorized_key' file
PUBKEYS_TO_COPY[0]="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAsMicXiH6F7zjhRrjLLyycFBUDHuMi4/wLuZtMteVt+lvC6/s8VtxMB+DDSUrctYV3Sp3Kn9r4tVGhaj6xsTcj45OpLJvSHd1rd+1ke8ehH7TrKWuvrIVkWCz78/1q+Ogx9Wc/c5eq9s5zRvSKFinLx1lxSPjytInlOUVYhp2H7Ofbz0YGItgCm67Cy38C8slmeHEP9EXFMEj4QKqv67leRdTy+POrYMWRqOtELGSIH7P11ImEcyvzldpInP6DOkEBzh7Zyr7059DOi4SuAVz9dSX6YFAZb0gllBU0qxey6z8HCsuZ68s7ahbsKSV9G4xEMAQFIuZtnfVjrK+TYzovw== valentino@albus.int.ingv.it"
PUBKEYS_TO_COPY[1]="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTPs3bE3LM0/YQADF6FO1/llv1/LjWI/P+qdtBOdpN6q0QJvxlYpx34uNgN1WD0x1Bb/rwU/aEXXMauhD+UuFEcs/IBi0/SrRYp8PhimFaZaFyUu/+biZ19zTlcSI3Rii9FOZfoWdet6JsDwquOz3BI+x28K8H2fHUWofBOS/eCfwxjQ80ncl/I0uUuXngnIyW6VACg88Peov6vau6BoJwumaBdB6G8PWizcm0vnTIXe+bf1FpMvAqT6jsLaqB6P0w5AAydLKoGSTjQDX1aiOKnMzMUXnFErwJfwzi553B6p4Do8EI82PZ7P2SSyN1BEH6wZZCF3KDADRr1ziER+EB valentino@pleo.int.ingv.it"
PUBKEYS_TO_COPY[2]="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyJKkfDIcVk2lsfJJcWVNyp1ysMPSiRBAfYC7Oxbxb1tyfxCbWqPVVADxOpDc9XKQBpBKe8bc9UMHPu+hUGj+HgEvXKhowgcXXryavxx1njygdC6JCpxWmePVHloRoRGXTrOaDDQn560M4iDJ/BvqX9cH56c0lPcGT4m2zDrZ7lFxfJkOphCt2M16deX8/oM2RLYPN6WkawkjrTUl+78tp0OwPpiviTy9UuauaofQvuFVVbI6fQ5pqfFd3JbvBEsG/ViklFSfTyMMKBkuzmsKyffl1859yFwvA5AibBsccmpAhxIxP1PTw1nIJyurAeN0FsevyGpuwx/uH5yo5GsVTQ== mtheo@june.int.ingv.it"
PUBKEYS_TO_COPY[3]="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA1D5JiVLutCnzu7yco5M2NdfBgHcvp1TqMdotIu+b2tFKPnKf+Sp7OxKnnTPBq7EKcgprcAPcAwmHXOrhoebn+ZFeCI//EMmmodN2LsjGv6FUjgZwWAF6H5IY9miL7mhJSfBNkN24vCRdY5xSbX3gguQFre1+6A30JPaEAGUx41bpeGajPYZ7G3BPp7heoabJO9I8lZlbmFz5VZtv5eCjMvHj+Xh72nxKv37nzeI32rrCJiFGOD2ECnAITmGKxxrNvqVWih/j4OMLf43k+Q0cUEFi6qBgNGV6hZZFgSmBtT+1xdXiOX+sCM9mG2wBnzzi/qijQkxqcXJxs1KuldC5ow== stefano@excuse.int.ingv.it"
PUBKEYS_TO_COPY[4]="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCyAiQ+tycNr/gYUead9Jq5rFP8Jl+wpzkHTmKAOe2mUO3+MpZ0V9WiFCqmYAo6Kk0FRPh6KX1r2n+ICrhcdHOyQu1vdrmmJp77w03dVpLBDCu83hNIMHMS3jADaKm2QH6KfwBoxVDTi38bJRl9bGwBCiFMB0G0lgU+NlWLe8d7etuQcy9cLI5O7srHvucQu6ksMZv9m0YBNnlVPIkQcDW+9fvN9uEB6rJxsMYWZ8xy13ck/6V+ljYFuHBb7TVB26b4ADiae8DPnitlre1OveSdtU5vwLBFZJaamMV0LX9lY3/Z+MvkMGUza8KbfJpTYjbBkyX8k0XsyD8MqnfcHtTF root@osiride.int.ingv.it"
PUBKEYS_TO_COPY[5]="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCz0gMdip6O8B91/mOkx+e7mo3XDuPmcX3e3iFd4/3sf/cDN3GUmaon/NVLXmgCs9UCXK63lzFfFWwI59A95I1vEP7fuWUVdMg1rz1eKtsMZ1G1LOwuiYCtjWr+YltKt6KeNjwpeLO9xsXfEFkzDKBxhzDEAHqvpkdONyoTi97c0jMijpwxrpDruecr88L1rh4PME+haWWP/2RL3l6bnUvDzIz+krlN37XUgqUbElpY06yJk2xN8vwAD3h88m2+BAHM5YCCoYMbxhLauQUsq9HG+JNE/CSDI7AsNeHVt0tFQ0+hdxETszxnE7sPSQpliR1MBZi7yFyoInqdZR4nQlfP root@osiride2"

setup_sshkey()
{
    local key=${1}
    local host=${2}
    local user=${3}

    key=$(echo $key | base64 --decode  | sed -e "s/\([^ ]\{20\}\) \([^ ]\{20\}\)/\1\n\2/g" -e "s/----- /-----\n/" -e "s/ -----/\n-----/");

    local keyfile=${SSHBASEDIR}/${host}.key

echo "Creating ssh key file.."
cat > "${TMPFILEKEY}" << EOF
$key
EOF

cat >> ${SSHBASEDIR}/config << EOF
Host $host
HostName $host
User $user
IdentityFile $keyfile
EOF

    # Generate the final ssh private key from the keyvault and place in root user context
    cp ${TMPFILEKEY} $keyfile

    # Add the git domain to known_hosts file for root
    ssh-keyscan $host >> ${SSHBASEDIR}/known_hosts

    chmod 400 $keyfile

    # remove the tmp key in ${TMPFILEKEY}
    # rm ${TMPFILEKEY}
}

echo_date() {
        DATE_ECHO=$( date +"%Y-%m-%d %H:%M:%S" )
        echo "[${DATE_ECHO}] - ${1}"
}

configure_public_keys()
{
	OLD_IFS="${IFS}"
	IFS=$'\n'
	for PUBKEY_TO_COPY in ${PUBKEYS_TO_COPY[*]}
	do
        	# root user
        	echo ${PUBKEY_TO_COPY} >> ~/.ssh/authorized_keys

        	# vmadmin user
        	echo ${PUBKEY_TO_COPY} >> /home/vmadmin/.ssh/authorized_keys
	done
	IFS="${OLD_IFS}"
}

configure_ulimit()
{
	echo_date "Set ulimit -n 65535"
	ulimit -n 65535
}

configure_apt()
{
    	echo_date "Installing packages:"

	# install needed bits in a loop because a lot of installs happen
	# on VM init, so won't be able to grab the dpkg lock immediately
	until apt-get -y update && apt-get -y install nginx git iptables fail2ban nload iftop sendmail
	do
		echo "Trying again"
		sleep 2
	done
	echo_date "Done"
	echo ""
}

configure_git()
{
    echo_date "Configuring \"git\":"
    local host=${1}
    local user=${2}
    local repo=${3}
    local key=${4}

    echo "Configuring git key $key"
    echo "Configuring git connectivity for $repo"
    echo "Registering git domain: $host"

    if [ ! -z "$key" ]; then
        setup_sshkey $key $host $user

        # remove html dir so we can clone into it
        rm -rf ${GITBASEDIRCURREPO}

        echo " Attemtping git clone of dncc repo.."
        echo " git clone git@$host:$user/$repo.git ${GITBASEDIRCURREPO}"
        git clone git@$host:$user/$repo.git ${GITBASEDIRCURREPO}
    else
        echo_date " No SSH private key. Skipping setup"
    fi
    echo_date "Done"
    echo ""
}

configure_nginx()
{
    local nginx_user=${1}
    local nginx_n_work_processes=${2}

	cd ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/nginx
	# Ubunt run nginx with www-data user
	sed -i'' -e "s/user[ \t][ \t]*[a-zA-z_-][a-zA-Z_-]*;/user  ${nginx_user};/" nginx.conf
	# Set number of nginx work processes
	sed -i'' -e "s/worker_processes  [0-9][0-9]*;/worker_processes  ${nginx_n_work_processes};/" nginx.conf

	cd ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/nginx/conf.d
	# Set 'server_name' with correct IP
	sed -i'' -e "s/server_name.*;/server_name  ${IP_LOADBALANCER};/" cnt.conf

	cd /etc/nginx
	mv nginx.conf nginx.conf.ORIGINAL
	ln -s ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/nginx/nginx.conf
	cd /etc/nginx/conf.d
	ln -s ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/nginx/conf.d/cnt.conf
	service nginx configtest
	service nginx restart
	echo ""
}

configure_iptables()
{
	echo_date "Configuring \"iptables\":"
	echo "Check installation:"
        dpkg-query -W -f='${Status} ${Version}\n' iptables
        RETURNED_VAL=${?}
	
        if (( ${RETURNED_VAL} == 0 )) && [ -d ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/firewall/ ]; then
                mkdir /etc/firewall
                cd /etc/firewall
                ln -s ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/firewall/firewall.openall.sh
                ln -s ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/firewall/firewall.rules_azure.sh firewall.rules.sh

                cd /etc/init.d
                ln -s ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/init.d/iptables

                /etc/init.d/iptables start
	else
		echo "Error configuring..."
        fi
	echo_date "Done"
	echo ""
}

configure_fail2ban()
{
	echo_date "Configuring \"fail2ban\":"
	echo "Check installation:"
        dpkg-query -W -f='${Status} ${Version}\n' fail2ban
        RETURNED_VAL=${?}

        if (( ${RETURNED_VAL} == 0 )) && [ -d ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/fail2ban/ ]; then
                service fail2ban stop

                DIR_FAIL2BAN="/etc/fail2ban"
                if [ -d ${DIR_FAIL2BAN} ]; then
                        cd ${DIR_FAIL2BAN}
                        if [ -f jail.local ]; then
                                mv jail.local jail.local__original
                        fi
			cat ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/fail2ban/jail_azure.local | sed "s/Fail2Ban-Azure-CNT/Fail2Ban-Azure-CNT-${SERVER_NAME}/g" > ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/fail2ban/jail_azure.local.new
			mv ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/fail2ban/jail_azure.local.new ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/fail2ban/jail_azure.local
                        ln -s ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/fail2ban/jail_azure.local ./jail.local
                fi

                # filter.d
                DIR_FAIL2BAN_FILTER="/etc/fail2ban/filter.d"
                if [ -d ${DIR_FAIL2BAN_FILTER} ]; then
                        cd ${DIR_FAIL2BAN_FILTER}
                        CONFIG_FILES="nginx-403.conf nginx-404.conf nginx-FDNE.conf nginx-filenotfound.conf nginx-noscript.conf nginx-req-limit.conf"
                        for CONFIG_FILE in ${CONFIG_FILES}; do
                                if [ -f ${CONFIG_FILE} ]; then
                                        mv ${CONFIG_FILE} ${CONFIG_FILE}__original
                                fi
                                ln -s ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/fail2ban/filter.d/${CONFIG_FILE}
                        done
                fi

                # action.d
                DIR_FAIL2BAN_ACTION="/etc/fail2ban/action.d"
                if [ -d ${DIR_FAIL2BAN_ACTION} ]; then
                        cd ${DIR_FAIL2BAN_ACTION}
                        CONFIG_FILES="sendmail-whois-lines.conf"
                        for CONFIG_FILE in ${CONFIG_FILES}; do
                                if [ -f ${CONFIG_FILE} ]; then
                                        mv ${CONFIG_FILE} ${CONFIG_FILE}__original
                                fi
                                ln -s ${GITBASEDIRCURREPO}/cnt.rm.ingv.it/root/etc/fail2ban/action.d/${CONFIG_FILE}
                        done
                fi

                service fail2ban start
	else
		echo "Error configuring..."
        fi
	echo_date "Done"
	echo ""
}

send_email()
{
# coma separated
RECIPIENTS="valentino.lauciani@ingv.it,matteo.quintiliani@ingv.it"

/usr/sbin/sendmail -v "${RECIPIENTS}" <<EOF
Subject:Azure - Started new instance "${SERVER_NAME}"
From:azure@azure.com

 DATE:        $( date +"%Y-%m-%d %H:%M:%S" )
 SERVER_NAME: ${SERVER_NAME}
 SERVER_IP:   ${SERVER_IP}

 OUTPUT:
 $( cat ${OUTPUTFILE} )

EOF
}

SEPLINE="============================================="

echo "$SEPLINE"  2>&1 >> ${OUTPUTFILE}
date  2>&1 >> ${OUTPUTFILE}
echo "$@"  2>&1 >> ${OUTPUTFILE}
echo "$SEPLINE"  2>&1 >> ${OUTPUTFILE}

configure_public_keys  2>&1 >> ${OUTPUTFILE}
configure_apt  2>&1 >> ${OUTPUTFILE}
configure_git $gitHostName $gitGroupName $gitRepoName $gitSshPrivateKey  2>&1 >> ${OUTPUTFILE}
configure_nginx $nginxUserName $nginxNumberOfWorkProcesses 2>&1 >> ${OUTPUTFILE}
configure_fail2ban  2>&1 >> ${OUTPUTFILE}
configure_iptables  2>&1 >> ${OUTPUTFILE}
configure_ulimit  2>&1 >> ${OUTPUTFILE}
send_email  2>&1 >> ${OUTPUTFILE}

cat $OUTPUTFILE
