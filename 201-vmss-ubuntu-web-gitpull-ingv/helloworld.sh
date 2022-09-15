#!/bin/bash

gitSshPrivateKey=$1
gitRepoName=$2
gitUserId=$3
gitHostName=gitlab.rm.ingv.it

# git@gitlab.rm.ingv.it:osiride/server_config.git
# gitSshPrivateKey=$1
# gitRepoName=server_config
# gitUserId=osiride
# gitHostName=gitlab.rm.ingv.it

OUTPUTFILE=/tmp/helloword.log

GITBASEDIR=/opt/gitwork/group__osiride
SSHBASEDIR=/root/.ssh
TMPFILEKEY=/tmp/tmp_key

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

configure_apt()
{
    echo "apt-get update and install" >> $OUTPUTFILE

	# install needed bits in a loop because a lot of installs happen
	# on VM init, so won't be able to grab the dpkg lock immediately
	until apt-get -y update && apt-get -y install nginx git
	do
		echo "Trying again"
		sleep 2
	done
}

configure_git()
{
    local key=${1}
    local host=${2}
    local user=${3}
    local repo=${4}

    echo "Configuring git key $key" >> $OUTPUTFILE
    echo "Configuring git connectivity for $repo" >> $OUTPUTFILE
    echo "Registering git domain: $host" >> $OUTPUTFILE

    if [ ! -z "$key" ]; then
        setup_sshkey $key $host $user

        # remove html dir so we can clone into it
        rm -rf ${GITBASEDIR}

        echo "Attemtping git clone of dncc repo.." >> $OUTPUTFILE
        echo "git clone git@$host:$user/$repo.git ${GITBASEDIR}" >> $OUTPUTFILE
        git clone git@$host:$user/$repo.git ${GITBASEDIR}
    else
        echo "no SSH private key. Skipping setup" >> $OUTPUTFILE
    fi 
}

SEPLINE="============================================="


echo "$SEPLINE" >> $OUTPUTFILE

echo "From gitlab.rm.ingv.it" >> $OUTPUTFILE
date >> $OUTPUTFILE
echo "Hello World" >> $OUTPUTFILE
echo "$@" >> $OUTPUTFILE
echo "$SEPLINE" >> $OUTPUTFILE

configure_apt
configure_git $gitSshPrivateKey $gitHostName $gitUserId $gitRepoName

cat $OUTPUTFILE
